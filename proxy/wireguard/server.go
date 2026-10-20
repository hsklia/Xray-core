package wireguard

import (
	"context"
	"crypto/ecdh"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"

	"github.com/xtls/xray-core/common/buf"
	c "github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
)

var nullDestination = net.TCPDestination(net.AnyIP, 0)

type Server struct {
	bindServer *netBindServer
	net        Tunnel
	usersMu    sync.RWMutex
	users      map[string]*protocol.MemoryUser
	peers      map[string]*MemoryAccount
	ambiguous  map[string]bool
	publicKey  string

	info          routingInfo
	policyManager policy.Manager
}

type routingInfo struct {
	ctx        context.Context
	dispatcher routing.Dispatcher
	inboundTag *session.Inbound
	contentTag *session.Content
}

func NewServer(ctx context.Context, conf *DeviceConfig) (*Server, error) {
	v := core.MustFromContext(ctx)

	endpoints, hasIPv4, hasIPv6, err := parseEndpoints(conf)
	if err != nil {
		return nil, err
	}

	server := &Server{
		bindServer: &netBindServer{
			netBind: netBind{
				dns: v.GetFeature(dns.ClientType()).(dns.Client),
				dnsOption: dns.IPOption{
					IPv4Enable: hasIPv4,
					IPv6Enable: hasIPv6,
				},
				workers:   int(conf.NumWorkers),
				readQueue: make(chan *netReadInfo),
			},
		},
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
	}

	tun, err := conf.createTun()(endpoints, int(conf.Mtu), server.forwardConnection)
	if err != nil {
		return nil, err
	}

	if err = tun.BuildDevice(createIPCRequest(conf), server.bindServer); err != nil {
		_ = tun.Close()
		return nil, err
	}
	server.net = tun
	server.users = make(map[string]*protocol.MemoryUser)
	server.peers = make(map[string]*MemoryAccount, len(conf.Peers))
	server.ambiguous = make(map[string]bool)
	for _, peer := range conf.Peers {
		a := configuredPeerAccount(peer)
		if previous := server.peers[a.peer.PublicKey]; previous != nil {
			// Repeated static entries append routes in UAPI. Reserve all of them
			// but do not pretend their final entry describes the effective peer:
			// earlier omitted keys/keepalive settings remain active in UAPI.
			a.prefixes = append(a.prefixes, previous.prefixes...)
			server.ambiguous[a.peer.PublicKey] = true
		}
		server.peers[a.peer.PublicKey] = a
	}
	if key, err := hex.DecodeString(conf.SecretKey); err == nil {
		if private, err := ecdh.X25519().NewPrivateKey(key); err == nil {
			server.publicKey = hex.EncodeToString(private.PublicKey().Bytes())
		}
	}

	return server, nil
}

// AddUser changes only a new peer. Rewriting an existing peer's preshared key,
// allowed IPs or endpoint can reset its live session, so conflicting retries are
// refused and identical retries do not touch the device at all.
func (s *Server) AddUser(ctx context.Context, user *protocol.MemoryUser) error {
	if user == nil || strings.TrimSpace(user.Email) == "" {
		return fmt.Errorf("WireGuard user email is required")
	}
	account, ok := user.Account.(*MemoryAccount)
	if !ok || account == nil || account.peer == nil {
		return fmt.Errorf("invalid WireGuard account")
	}
	if account.peer.Endpoint != "" {
		return fmt.Errorf("live WireGuard inbound peers must not set an endpoint")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.usersMu.Lock()
	defer s.usersMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.net == nil {
		return fmt.Errorf("WireGuard device is closed")
	}
	if account.peer.PublicKey == s.publicKey {
		return fmt.Errorf("WireGuard peer cannot use the server public key")
	}
	if s.ambiguous[account.peer.PublicKey] {
		return fmt.Errorf("WireGuard public key has multiple static configurations and cannot be adopted safely")
	}
	if existing := s.users[user.Email]; existing != nil {
		if existing.Account.Equals(account) && existing.Level == user.Level {
			return nil
		}
		return fmt.Errorf("WireGuard email already belongs to a different account")
	}
	for email, existing := range s.users {
		if existing.Account.(*MemoryAccount).peer.PublicKey == account.peer.PublicKey && email != user.Email {
			return fmt.Errorf("WireGuard public key already belongs to another account")
		}
	}
	if existing := s.peers[account.peer.PublicKey]; existing != nil {
		if !existing.Equals(account) {
			return fmt.Errorf("WireGuard public key already has a different configuration")
		}
		// A restart loaded this persisted peer without its management email. Adopt
		// it without applying any UAPI update to its active handshake state.
	} else {
		for _, existing := range s.peers {
			for _, current := range existing.prefixes {
				for _, next := range account.prefixes {
					if current.Overlaps(next) {
						return fmt.Errorf("WireGuard allowed IP overlaps an existing peer")
					}
				}
			}
		}
		var ipc strings.Builder
		fmt.Fprintf(&ipc, "public_key=%s\n", account.peer.PublicKey)
		if account.peer.PreSharedKey != "" {
			fmt.Fprintf(&ipc, "preshared_key=%s\n", account.peer.PreSharedKey)
		}
		for _, prefix := range account.peer.AllowedIps {
			fmt.Fprintf(&ipc, "allowed_ip=%s\n", prefix)
		}
		fmt.Fprintf(&ipc, "persistent_keepalive_interval=%d\n", account.peer.KeepAlive)
		if err := s.net.IpcSet(ipc.String()); err != nil {
			// UAPI is incremental rather than transactional. Only this previously
			// absent key may have been created, so cleanup cannot touch old peers.
			if cleanup := s.net.IpcSet("public_key=" + account.peer.PublicKey + "\nremove=true\n"); cleanup != nil {
				return fmt.Errorf("adding WireGuard peer failed: %w; cleanup failed: %v", err, cleanup)
			}
			return err
		}
		s.peers[account.peer.PublicKey] = account
	}
	copy := *user
	s.users[user.Email] = &copy
	return nil
}

func (s *Server) RemoveUser(ctx context.Context, email string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.usersMu.Lock()
	defer s.usersMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.net == nil {
		return fmt.Errorf("WireGuard device is closed")
	}
	user := s.users[email]
	if user == nil {
		// Initial peers have no email in this older protobuf. Claiming success
		// before they have been adopted would leave a revoked persisted key live
		// and suppress the caller's legacy error handling after a core restart.
		return fmt.Errorf("WireGuard user is unknown or has not been adopted")
	}
	key := user.Account.(*MemoryAccount).peer.PublicKey
	if err := s.net.IpcSet("public_key=" + key + "\nremove=true\n"); err != nil {
		return err
	}
	delete(s.users, email)
	delete(s.peers, key)
	return nil
}

func (s *Server) GetUser(_ context.Context, email string) *protocol.MemoryUser {
	s.usersMu.RLock()
	defer s.usersMu.RUnlock()
	if user := s.users[email]; user != nil {
		copy := *user
		return &copy
	}
	return nil
}

func (s *Server) GetUsers(_ context.Context) []*protocol.MemoryUser {
	s.usersMu.RLock()
	defer s.usersMu.RUnlock()
	users := make([]*protocol.MemoryUser, 0, len(s.users))
	for _, user := range s.users {
		copy := *user
		users = append(users, &copy)
	}
	return users
}

func (s *Server) GetUsersCount(context.Context) int64 {
	s.usersMu.RLock()
	defer s.usersMu.RUnlock()
	return int64(len(s.users))
}

func (s *Server) Close() error {
	s.usersMu.Lock()
	defer s.usersMu.Unlock()
	if s.net == nil {
		return nil
	}
	err := s.net.Close()
	s.net = nil
	s.users = nil
	s.peers = nil
	s.ambiguous = nil
	return err
}

// Network implements proxy.Inbound.
func (*Server) Network() []net.Network {
	return []net.Network{net.Network_UDP}
}

// Process implements proxy.Inbound.
func (s *Server) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	s.info = routingInfo{
		ctx:        ctx,
		dispatcher: dispatcher,
		inboundTag: session.InboundFromContext(ctx),
		contentTag: session.ContentFromContext(ctx),
	}

	ep, err := s.bindServer.ParseEndpoint(conn.RemoteAddr().String())
	if err != nil {
		return err
	}

	nep := ep.(*netEndpoint)
	nep.conn = conn

	reader := buf.NewPacketReader(conn)
	for {
		mb, err := reader.ReadMultiBuffer()
		if err != nil {
			nep.conn = nil
			buf.ReleaseMulti(mb)
			return err
		}

		for i, b := range mb {

			rawBytes := b.Bytes()
			if b.Len() > 3 {
				rawBytes[1] = 0
				rawBytes[2] = 0
				rawBytes[3] = 0
			}

			select {
			case s.bindServer.readQueue <- &netReadInfo{
				buff:     b,
				endpoint: nep,
			}:
			case <-s.bindServer.closedCh:
				nep.conn = nil
				buf.ReleaseMulti(mb[i:])
				return errors.New("bind closed")
			}
		}
	}
}

func (s *Server) forwardConnection(dest net.Destination, conn net.Conn) {
	if s.info.dispatcher == nil {
		errors.LogError(s.info.ctx, "unexpected: dispatcher == nil")
		return
	}

	ctx, cancel := context.WithCancel(core.ToBackgroundDetachedContext(s.info.ctx))
	sid := session.NewID()
	ctx = c.ContextWithID(ctx, sid)
	inbound := session.Inbound{} // since promiscuousModeHandler mixed-up context, we shallow copy inbound (tag) and content (configs)
	if s.info.inboundTag != nil {
		inbound = *s.info.inboundTag
	}
	inbound.Name = "wireguard"
	inbound.CanSpliceCopy = 3

	// overwrite the source to use the tun address for each sub context.
	// Since gvisor.ForwarderRequest doesn't provide any info to associate the sub-context with the Parent context
	// Currently we have no way to link to the original source address
	inbound.Source = net.DestinationFromAddr(conn.RemoteAddr())
	ctx = session.ContextWithInbound(ctx, &inbound)
	content := new(session.Content)
	if s.info.contentTag != nil {
		content.SniffingRequest = s.info.contentTag.SniffingRequest
	}
	ctx = session.ContextWithContent(ctx, content)
	ctx = session.SubContextFromMuxInbound(ctx)

	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   nullDestination,
		To:     dest,
		Status: log.AccessAccepted,
		Reason: "",
	})

	err := s.info.dispatcher.DispatchLink(ctx, dest, &transport.Link{
		Reader: buf.NewReader(conn),
		Writer: buf.NewWriter(conn),
	})

	if err != nil {
		errors.LogInfoInner(ctx, err, "connection ends")
	}

	cancel()
	conn.Close()
}
