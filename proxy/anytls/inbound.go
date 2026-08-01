package anytls

import (
	"bytes"
	"context"
	"strconv"
	"strings"
	"sync"

	singanytls "github.com/anytls/sing-anytls"
	"github.com/anytls/sing-anytls/padding"
	A "github.com/sagernet/sing/common/auth"
	B "github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/singbridge"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func init() {
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewServer(ctx, config.(*ServerConfig))
	}))
}

var (
	_ N.TCPConnectionHandlerEx = (*Inbound)(nil)
	// Without this the handler service's type assertion would fail at runtime and
	// hot-add would silently no-op.
	_ proxy.UserManager = (*Inbound)(nil)
)

// Inbound is an inbound connection handler that speaks the anytls protocol. The
// wire format is handled by github.com/anytls/sing-anytls; this type is the
// adapter between it and Xray's dispatcher, in the same shape as
// proxy/shadowsocks_2022.
type Inbound struct {
	access        sync.RWMutex
	users         []*protocol.MemoryUser
	service       *singanytls.Service
	fallbacks     map[string]map[string]map[string]*Fallback // or nil
	policyManager policy.Manager
}

func NewServer(ctx context.Context, config *ServerConfig) (*Inbound, error) {
	users := make([]*protocol.MemoryUser, 0, len(config.Users))
	for i, user := range config.Users {
		if user.Email == "" {
			u := uuid.New()
			user.Email = "unnamed-user-" + strconv.Itoa(i) + "-" + u.String()
		}
		memoryUser, err := user.ToMemoryUser()
		if err != nil {
			return nil, errors.New("failed to parse anytls user").Base(err).AtError()
		}
		account, ok := memoryUser.Account.(*MemoryAccount)
		if !ok || account.Password == "" {
			// Hard failure: an empty password must never become a valid credential,
			// and the only way to get here is a code-level defect, since the JSON
			// layer already rejects a blank one.
			return nil, errors.New("anytls user ", memoryUser.Email, " has no password").AtError()
		}
		// Degrade rather than refuse the config. Xray rejects the WHOLE config when
		// any one inbound fails to build, so a single bad pair of accounts would take
		// every other inbound on the box down with it; and this path also carries DB
		// imports and restores, which no panel-side guard sees. Dropping the later
		// account is the honest outcome anyway: it could never have worked.
		if owner, exists := duplicatePasswordOwner(users, account.Password); exists {
			errors.LogWarning(ctx, "anytls: ignoring user ", memoryUser.Email,
				": its password is already used by ", owner, ", and the password is the only thing a client sends to identify itself")
			continue
		}
		users = append(users, memoryUser)
	}

	v := core.MustFromContext(ctx)
	inbound := &Inbound{
		users:         users,
		fallbacks:     buildFallbacks(config.Fallbacks),
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
	}

	scheme := []byte(config.PaddingScheme)
	if len(bytes.TrimSpace(scheme)) == 0 {
		// NewService rejects an empty scheme with "incorrect padding scheme format".
		scheme = padding.DefaultPaddingScheme
	}
	serviceConfig := singanytls.ServiceConfig{
		PaddingScheme: scheme,
		Users:         toServiceUsers(users),
		Handler:       inbound,
		Logger:        singbridge.NewLogger(errors.New),
	}
	if inbound.fallbacks != nil {
		serviceConfig.FallbackHandler = &fallbackHandler{inbound: inbound}
	}
	service, err := singanytls.NewService(serviceConfig)
	if err != nil {
		return nil, errors.New("failed to create anytls service").Base(err).AtError()
	}
	inbound.service = service

	return inbound, nil
}

// duplicatePasswordOwner reports the email of the user already holding password.
//
// A password is the only thing an anytls client sends to identify itself, so two
// accounts sharing one are indistinguishable on the wire and all of the loser's
// traffic would be booked against the winner.
func duplicatePasswordOwner(users []*protocol.MemoryUser, password string) (string, bool) {
	for _, u := range users {
		if account, ok := u.Account.(*MemoryAccount); ok && account.Password == password {
			return u.Email, true
		}
	}
	return "", false
}

func toServiceUsers(users []*protocol.MemoryUser) []singanytls.User {
	serviceUsers := make([]singanytls.User, 0, len(users))
	for _, u := range users {
		account, ok := u.Account.(*MemoryAccount)
		if !ok {
			continue
		}
		// Name is what comes back out of auth.UserFromContext, so it has to be the
		// account email: that is the key everything downstream is booked against.
		serviceUsers = append(serviceUsers, singanytls.User{Name: u.Email, Password: account.Password})
	}
	return serviceUsers
}

// syncUsers pushes the whole user list into the service. Must be called with
// access held.
func (i *Inbound) syncUsers() {
	i.service.UpdateUsers(toServiceUsers(i.users))
}

// AddUser implements proxy.UserManager.AddUser().
func (i *Inbound) AddUser(ctx context.Context, u *protocol.MemoryUser) error {
	account, ok := u.Account.(*MemoryAccount)
	if !ok || account.Password == "" {
		return errors.New("anytls user ", u.Email, " has no password")
	}

	i.access.Lock()
	defer i.access.Unlock()

	if u.Email != "" {
		for _, existing := range i.users {
			if strings.EqualFold(existing.Email, u.Email) {
				return errors.New("User ", u.Email, " already exists.")
			}
		}
	}
	// Hard error here, unlike the config path: this is a single operator action,
	// nothing else goes down with it, and the caller can report it.
	if owner, exists := duplicatePasswordOwner(i.users, account.Password); exists {
		return errors.New("anytls user ", u.Email, " shares a password with ", owner)
	}

	i.users = append(i.users, u)
	i.syncUsers()
	return nil
}

// RemoveUser implements proxy.UserManager.RemoveUser().
func (i *Inbound) RemoveUser(ctx context.Context, email string) error {
	if email == "" {
		return errors.New("Email must not be empty.")
	}

	i.access.Lock()
	defer i.access.Unlock()

	idx := -1
	for index, u := range i.users {
		if strings.EqualFold(u.Email, email) {
			idx = index
			break
		}
	}
	if idx == -1 {
		return errors.New("User ", email, " not found.")
	}

	ulen := len(i.users)
	i.users[idx] = i.users[ulen-1]
	i.users[ulen-1] = nil
	i.users = i.users[:ulen-1]

	i.syncUsers()
	return nil
}

// GetUser implements proxy.UserManager.GetUser().
func (i *Inbound) GetUser(ctx context.Context, email string) *protocol.MemoryUser {
	if email == "" {
		return nil
	}

	i.access.RLock()
	defer i.access.RUnlock()

	for _, u := range i.users {
		if strings.EqualFold(u.Email, email) {
			return u
		}
	}
	return nil
}

// GetUsers implements proxy.UserManager.GetUsers().
func (i *Inbound) GetUsers(ctx context.Context) []*protocol.MemoryUser {
	i.access.RLock()
	defer i.access.RUnlock()

	dst := make([]*protocol.MemoryUser, len(i.users))
	copy(dst, i.users)
	return dst
}

// GetUsersCount implements proxy.UserManager.GetUsersCount().
func (i *Inbound) GetUsersCount(context.Context) int64 {
	i.access.RLock()
	defer i.access.RUnlock()

	return int64(len(i.users))
}

// Network implements proxy.Inbound.Network().
func (i *Inbound) Network() []net.Network {
	return []net.Network{net.Network_TCP, net.Network_UNIX}
}

// Process implements proxy.Inbound.Process().
func (i *Inbound) Process(ctx context.Context, network net.Network, connection stat.Connection, dispatcher routing.Dispatcher) error {
	inbound := session.InboundFromContext(ctx)
	inbound.Name = "anytls"
	inbound.CanSpliceCopy = 3

	var source M.Socksaddr
	if inbound.Source.IsValid() {
		source = M.ParseSocksaddr(inbound.Source.NetAddr())
	}

	ctx = session.ContextWithDispatcher(ctx, dispatcher)

	// TLS/REALITY has already been terminated by Xray's transport layer, so the
	// connection handed over here is the plaintext NewConnection expects. It runs
	// the session inline and returns only once the session is over, which is
	// exactly Process' contract, so onClose has nothing left to do.
	return singbridge.ReturnError(i.service.NewConnection(ctx, connection, source, nil))
}

// NewConnectionEx implements N.TCPConnectionHandlerEx: one call per stream
// multiplexed over the anytls session, each on its own goroutine.
func (i *Inbound) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	err := i.handleStream(ctx, conn, source, destination)
	// The session does not close streams for us, and nothing else will: unlike a
	// plain inbound, Process outlives every individual stream.
	conn.Close()
	if err != nil && !E.IsClosedOrCanceled(err) {
		errors.LogInfo(ctx, "anytls: ", err.Error())
	}
	if onClose != nil {
		onClose(err)
	}
}

func (i *Inbound) handleStream(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr) error {
	userName, _ := A.UserFromContext[string](ctx)
	user := i.GetUser(ctx, userName)
	if user == nil {
		return errors.New("unknown user ", userName)
	}

	// Every stream of one anytls session shares this context, so each gets its own
	// copy of the inbound metadata: the dispatcher reads User off it and the speed
	// limiter writes CanSpliceCopy back, which would race across streams otherwise.
	inbound := *session.InboundFromContext(ctx)
	inbound.Name = "anytls"
	inbound.CanSpliceCopy = 3
	inbound.User = user
	ctx = session.ContextWithInbound(ctx, &inbound)

	dispatcher := session.DispatcherFromContext(ctx)
	if dispatcher == nil {
		return errors.New("no dispatcher in context")
	}

	// anytls has no UDP of its own: clients tunnel it as UDP-over-TCP to a magic
	// address. Without this the stream would be dispatched as a TCP connection to
	// a domain that does not exist and UDP would silently never work.
	if destination.IsFqdn() {
		switch destination.Fqdn {
		case uot.MagicAddress:
			request, err := uot.ReadRequest(conn)
			if err != nil {
				return errors.New("failed to read UDP-over-TCP request").Base(err)
			}
			return i.handlePacketStream(ctx, uot.NewConn(conn, *request), source, request.Destination, user, dispatcher)
		case uot.LegacyMagicAddress:
			// v1 has no request header at all; the destination arrives with the
			// first packet.
			return i.handlePacketStream(ctx, uot.NewConn(conn, uot.Request{}), source, M.Socksaddr{}, user, dispatcher)
		}
	}

	dest := singbridge.ToDestination(destination, net.Network_TCP)
	if !dest.IsValid() {
		return errors.New("invalid destination ", destination.String())
	}

	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   source,
		To:     dest,
		Status: log.AccessAccepted,
		Email:  user.Email,
	})
	errors.LogInfo(ctx, "tunnelling request to tcp:", dest.NetAddr())

	link, err := dispatcher.Dispatch(ctx, dest)
	if err != nil {
		return err
	}
	return singbridge.CopyConn(ctx, conn, link, conn)
}

func (i *Inbound) handlePacketStream(ctx context.Context, conn *uot.Conn, source M.Socksaddr, destination M.Socksaddr, user *protocol.MemoryUser, dispatcher routing.Dispatcher) error {
	var first *B.Buffer
	if !destination.IsValid() {
		first = B.NewPacket()
		addr, err := conn.ReadPacket(first)
		if err != nil {
			first.Release()
			return errors.New("failed to read first UDP-over-TCP packet").Base(err)
		}
		destination = addr
	}
	defer func() {
		if first != nil {
			first.Release()
		}
	}()

	dest := singbridge.ToDestination(destination, net.Network_UDP)
	if !dest.IsValid() {
		return errors.New("invalid UDP destination ", destination.String())
	}

	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   source,
		To:     dest,
		Status: log.AccessAccepted,
		Email:  user.Email,
	})
	errors.LogInfo(ctx, "tunnelling request to udp:", dest.NetAddr())

	link, err := dispatcher.Dispatch(ctx, dest)
	if err != nil {
		return err
	}
	outConn := &singbridge.PacketConnWrapper{
		Reader: link.Reader,
		Writer: link.Writer,
		Conn:   conn,
		Dest:   dest,
	}
	if first != nil {
		if err := outConn.WritePacket(first, destination); err != nil {
			return err
		}
	}
	return singbridge.ReturnError(bufio.CopyPacketConn(ctx, conn, outConn))
}
