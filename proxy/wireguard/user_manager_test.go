package wireguard

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

var _ proxy.UserManager = (*Server)(nil)

func hotPeer(t *testing.T, address string) *PeerConfig {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &PeerConfig{
		PublicKey:    hex.EncodeToString(key.PublicKey().Bytes()),
		PreSharedKey: strings.Repeat("1a", 32),
		AllowedIps:   []string{address},
		KeepAlive:    25,
	}
}

func hotUser(t *testing.T, email string, peer *PeerConfig) *protocol.MemoryUser {
	t.Helper()
	// Exercise the exact protobuf conversion the HandlerService uses.
	user, err := (&protocol.User{Email: email, Account: serial.ToTypedMessage(peer)}).ToMemoryUser()
	if err != nil {
		t.Fatal(err)
	}
	return user
}

func TestWireGuardPeerAccountValidation(t *testing.T) {
	valid := hotPeer(t, "10.0.0.2/32")
	for name, change := range map[string]func(*PeerConfig){
		"missing public key": func(p *PeerConfig) { p.PublicKey = "" },
		"zero public key":    func(p *PeerConfig) { p.PublicKey = strings.Repeat("0", 64) },
		"invalid hex key":    func(p *PeerConfig) { p.PublicKey = strings.Repeat("z", 64) },
		"injected key":       func(p *PeerConfig) { p.PublicKey += "\nreplace_peers=true" },
		"bad preshared key":  func(p *PeerConfig) { p.PreSharedKey = "wrong" },
		"missing addresses":  func(p *PeerConfig) { p.AllowedIps = nil },
		"invalid address":    func(p *PeerConfig) { p.AllowedIps = []string{"10.0.0.2"} },
		"injected address":   func(p *PeerConfig) { p.AllowedIps = []string{"10.0.0.2/32\nreplace_peers=true"} },
		"mapped IPv4":        func(p *PeerConfig) { p.AllowedIps = []string{"::ffff:10.0.0.2/128"} },
		"keepalive overflow": func(p *PeerConfig) { p.KeepAlive = 65536 },
	} {
		t.Run(name, func(t *testing.T) {
			p := &PeerConfig{PublicKey: valid.PublicKey, PreSharedKey: valid.PreSharedKey, KeepAlive: valid.KeepAlive, AllowedIps: append([]string(nil), valid.AllowedIps...)}
			change(p)
			if _, err := p.AsAccount(); err == nil {
				t.Fatal("invalid peer account was accepted")
			}
		})
	}
	account, err := valid.AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	valid.AllowedIps[0] = "10.0.0.99/32"
	copy := account.ToProto().(*PeerConfig)
	if copy.AllowedIps[0] != "10.0.0.2/32" {
		t.Fatal("account retains caller-owned configuration")
	}
	copy.PublicKey = "changed"
	if account.ToProto().(*PeerConfig).PublicKey == "changed" {
		t.Fatal("account returned mutable configuration")
	}
}

type hotTunnel struct {
	requests []string
	failNext bool
	closed   bool
}

func (*hotTunnel) BuildDevice(string, conn.Bind) error { return nil }
func (t *hotTunnel) IpcSet(ipc string) error {
	t.requests = append(t.requests, ipc)
	if t.failNext {
		t.failNext = false
		return errors.New("injected UAPI failure")
	}
	return nil
}
func (*hotTunnel) DialContextTCPAddrPort(context.Context, netip.AddrPort) (net.Conn, error) {
	return nil, errors.New("unused")
}
func (*hotTunnel) DialUDPAddrPort(netip.AddrPort, netip.AddrPort) (net.Conn, error) {
	return nil, errors.New("unused")
}
func (t *hotTunnel) Close() error { t.closed = true; return nil }

func hotServer(tun Tunnel) *Server {
	return &Server{net: tun, users: map[string]*protocol.MemoryUser{}, peers: map[string]*MemoryAccount{}}
}

func TestWireGuardLiveAddRejectsConflictsBeforeUAPI(t *testing.T) {
	tun := &hotTunnel{}
	s := hotServer(tun)
	first := hotPeer(t, "10.0.0.2/32")
	if err := s.AddUser(context.Background(), hotUser(t, "first", first)); err != nil {
		t.Fatal(err)
	}
	for _, user := range []*protocol.MemoryUser{
		hotUser(t, "first", hotPeer(t, "10.0.0.3/32")),
		hotUser(t, "different email", first),
		hotUser(t, "same IP", hotPeer(t, "10.0.0.2/32")),
		hotUser(t, "overlapping subnet", hotPeer(t, "10.0.0.0/24")),
	} {
		if err := s.AddUser(context.Background(), user); err == nil {
			t.Fatal("conflicting peer was accepted")
		}
	}
	withEndpoint := hotPeer(t, "10.0.0.3/32")
	withEndpoint.Endpoint = "127.0.0.1:9999"
	if err := s.AddUser(context.Background(), hotUser(t, "endpoint", withEndpoint)); err == nil {
		t.Fatal("live inbound peer with endpoint was accepted")
	}
	s.publicKey = hotPeer(t, "10.0.0.4/32").PublicKey
	self := hotPeer(t, "10.0.0.4/32")
	self.PublicKey = s.publicKey
	if err := s.AddUser(context.Background(), hotUser(t, "self", self)); err == nil {
		t.Fatal("server's own public key was accepted")
	}
	if len(tun.requests) != 1 {
		t.Fatalf("rejected peer changed UAPI: %d requests", len(tun.requests))
	}
	request := tun.requests[0]
	for _, forbidden := range []string{"replace_peers", "replace_allowed_ips", "private_key", "listen_port", "endpoint="} {
		if strings.Contains(request, forbidden) {
			t.Fatalf("live addition changed unrelated state: %q", forbidden)
		}
	}
}

func TestWireGuardLiveAddRetryAndFailure(t *testing.T) {
	tun := &hotTunnel{}
	s := hotServer(tun)
	user := hotUser(t, "first", hotPeer(t, "10.0.0.2/32"))
	if err := s.AddUser(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	if err := s.AddUser(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	if len(tun.requests) != 1 {
		t.Fatal("identical retry touched an existing peer")
	}
	tun.failNext = true
	failed := hotUser(t, "failed", hotPeer(t, "10.0.0.3/32"))
	if err := s.AddUser(context.Background(), failed); err == nil {
		t.Fatal("expected UAPI failure")
	}
	if s.GetUser(context.Background(), "failed") != nil || s.GetUsersCount(context.Background()) != 1 {
		t.Fatal("failed addition was published")
	}
	cleanup := tun.requests[len(tun.requests)-1]
	if cleanup != "public_key="+failed.Account.(*MemoryAccount).peer.PublicKey+"\nremove=true\n" {
		t.Fatal("failed addition did not clean up only its own peer")
	}
	if err := s.AddUser(context.Background(), failed); err != nil {
		t.Fatal(err)
	}
	tun.failNext = true
	if err := s.RemoveUser(context.Background(), "first"); err == nil {
		t.Fatal("expected remove failure")
	}
	if s.GetUser(context.Background(), "first") == nil {
		t.Fatal("failed removal forgot live peer")
	}
	if err := s.RemoveUser(context.Background(), "first"); err != nil {
		t.Fatal(err)
	}
	if s.GetUser(context.Background(), "first") != nil || s.GetUsersCount(context.Background()) != 1 {
		t.Fatal("peer not removed")
	}
}

func TestWireGuardLiveAddConcurrent(t *testing.T) {
	tun := &hotTunnel{}
	s := hotServer(tun)
	const count = 32
	users := make([]*protocol.MemoryUser, count)
	for i := range users {
		users[i] = hotUser(t, fmt.Sprint(i), hotPeer(t, fmt.Sprintf("10.0.0.%d/32", i+2)))
	}
	var wg sync.WaitGroup
	for _, user := range users {
		wg.Add(1)
		go func(user *protocol.MemoryUser) {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				if err := s.AddUser(context.Background(), user); err != nil {
					t.Error(err)
				}
				s.GetUser(context.Background(), user.Email)
				s.GetUsers(context.Background())
				s.GetUsersCount(context.Background())
			}
		}(user)
	}
	wg.Wait()
	if len(tun.requests) != count || s.GetUsersCount(context.Background()) != count {
		t.Fatal("concurrent retries duplicated or lost a peer")
	}
}

func TestWireGuardRealDevicePreservesExistingPeerAcrossLiveAdd(t *testing.T) {
	instance, err := core.New(&core.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = instance.Close() })
	ctx := context.WithValue(context.Background(), core.XrayKey(1), instance)
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	initial := hotPeer(t, "10.0.0.2/32")
	inert := hotPeer(t, "10.0.0.99/32")
	inert.AllowedIps = nil // Previously valid static configurations must still load.
	duplicate := hotPeer(t, "10.0.0.98/32")
	duplicateTail := &PeerConfig{PublicKey: duplicate.PublicKey, AllowedIps: []string{"10.0.0.99/32"}}
	s, err := NewServer(ctx, &DeviceConfig{SecretKey: hex.EncodeToString(key.Bytes()), Endpoint: []string{"10.0.0.1/32"}, Mtu: 1420, NumWorkers: 1, Peers: []*PeerConfig{initial, inert, duplicate, duplicateTail}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	tun := s.net.(*gvisorNet)
	dev := tun.device
	var initialKey device.NoisePublicKey
	if err := initialKey.FromHex(initial.PublicKey); err != nil {
		t.Fatal(err)
	}
	original := dev.LookupPeer(initialKey)
	if original == nil {
		t.Fatal("initial peer absent")
	}
	// Repeated static entries retain the first entry's PSK/keepalive and union
	// both routes in UAPI. The final descriptor alone cannot safely identify that
	// effective peer; reject adoption and reserve every initial address.
	if err := s.AddUser(ctx, hotUser(t, "ambiguous", duplicateTail)); err == nil {
		t.Fatal("ambiguous duplicate static peer was adopted")
	}
	for _, address := range []string{"10.0.0.98/32", "10.0.0.99/32"} {
		if err := s.AddUser(ctx, hotUser(t, "must-not-steal", hotPeer(t, address))); err == nil {
			t.Fatalf("address %s from a duplicate static entry was not reserved", address)
		}
	}
	// Immediately after restart the protobuf peer has no management email. A
	// legacy revocation must fail explicitly rather than falsely confirm that a
	// still-active persisted key has been removed.
	if err := s.RemoveUser(ctx, "initial"); err == nil {
		t.Fatal("unadopted persisted peer removal reported false success")
	}
	if dev.LookupPeer(initialKey) != original {
		t.Fatal("unknown email changed an unrelated persisted peer")
	}
	// A persisted peer can be adopted after restart with no UAPI rewrite.
	if err := s.AddUser(ctx, hotUser(t, "initial", initial)); err != nil {
		t.Fatal(err)
	}
	second := hotPeer(t, "10.0.0.3/32")
	if err := s.AddUser(ctx, hotUser(t, "second", second)); err != nil {
		t.Fatal(err)
	}
	var secondKey device.NoisePublicKey
	if err := secondKey.FromHex(second.PublicKey); err != nil {
		t.Fatal(err)
	}
	if tun.device != dev || dev.LookupPeer(initialKey) != original || dev.LookupPeer(secondKey) == nil {
		t.Fatal("live add replaced the device or an existing peer")
	}
	if err := s.RemoveUser(ctx, "second"); err != nil {
		t.Fatal(err)
	}
	if tun.device != dev || dev.LookupPeer(initialKey) != original || dev.LookupPeer(secondKey) != nil {
		t.Fatal("removal changed another peer or failed to remove the requested peer")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.AddUser(ctx, hotUser(t, "after close", hotPeer(t, "10.0.0.4/32"))); err == nil {
		t.Fatal("closed device accepted a peer")
	}
}

func TestWireGuardEstablishedTCPSessionSurvivesLivePeerAddition(t *testing.T) {
	serverKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	initial := hotPeer(t, "10.0.0.2/32")
	initial.PublicKey = hex.EncodeToString(clientKey.PublicKey().Bytes())
	serverTun, err := createGVisorTun([]netip.Addr{netip.MustParseAddr("10.0.0.1")}, 1420, func(_ net.Destination, connection net.Conn) {
		defer connection.Close()
		_, _ = io.Copy(connection, connection)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = serverTun.Close() })
	if err := serverTun.BuildDevice(createIPCRequest(&DeviceConfig{
		IsClient:  true, // Bind owns a random loopback port rather than Xray's placeholder port.
		SecretKey: hex.EncodeToString(serverKey.Bytes()), Peers: []*PeerConfig{initial},
	}), conn.NewDefaultBind()); err != nil {
		t.Fatal(err)
	}
	serverDevice := serverTun.(*gvisorNet).device
	configuration, err := serverDevice.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	var port string
	for _, line := range strings.Split(configuration, "\n") {
		if value, ok := strings.CutPrefix(line, "listen_port="); ok {
			port = value
		}
	}
	if port == "" || port == "0" {
		t.Fatal("userspace WireGuard server did not bind a port")
	}
	clientTun, err := createGVisorTun([]netip.Addr{netip.MustParseAddr("10.0.0.2")}, 1420, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = clientTun.Close() })
	if err := clientTun.BuildDevice(createIPCRequest(&DeviceConfig{
		IsClient: true, SecretKey: hex.EncodeToString(clientKey.Bytes()),
		Peers: []*PeerConfig{{
			PublicKey:    hex.EncodeToString(serverKey.PublicKey().Bytes()),
			PreSharedKey: initial.PreSharedKey, Endpoint: "127.0.0.1:" + port,
			AllowedIps: []string{"10.0.0.1/32"},
		}},
	}), conn.NewDefaultBind()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	connection, err := clientTun.DialContextTCPAddrPort(ctx, netip.MustParseAddrPort("10.0.0.1:9999"))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	echo := func(connection net.Conn, value string) {
		t.Helper()
		if err := connection.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(connection, value); err != nil {
			t.Fatal(err)
		}
		response := make([]byte, len(value))
		if _, err := io.ReadFull(connection, response); err != nil {
			t.Fatal(err)
		}
		if string(response) != value {
			t.Fatal("established session returned corrupt data")
		}
	}
	account, err := initial.AsAccount()
	if err != nil {
		t.Fatal(err)
	}
	s := hotServer(serverTun)
	s.publicKey = hex.EncodeToString(serverKey.PublicKey().Bytes())
	s.peers[initial.PublicKey] = account.(*MemoryAccount)
	echo(connection, "before live add")
	var key device.NoisePublicKey
	if err := key.FromHex(initial.PublicKey); err != nil {
		t.Fatal(err)
	}
	original := serverDevice.LookupPeer(key)
	if original == nil {
		t.Fatal("established peer disappeared")
	}
	for i := 0; i < 8; i++ {
		peer := hotPeer(t, fmt.Sprintf("10.0.0.%d/32", i+3))
		newClientKey, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		peer.PublicKey = hex.EncodeToString(newClientKey.PublicKey().Bytes())
		user := hotUser(t, fmt.Sprintf("hot-%d", i), peer)
		if err := s.AddUser(ctx, user); err != nil {
			t.Fatal(err)
		}
		echo(connection, fmt.Sprintf("same encrypted TCP connection after add %d", i))
		if i == 0 {
			// The newly admitted peer must work before any core or TUN restart.
			newClientTun, err := createGVisorTun([]netip.Addr{netip.MustParseAddr("10.0.0.3")}, 1420, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = newClientTun.Close() })
			if err := newClientTun.BuildDevice(createIPCRequest(&DeviceConfig{
				IsClient: true, SecretKey: hex.EncodeToString(newClientKey.Bytes()),
				Peers: []*PeerConfig{{
					PublicKey:    hex.EncodeToString(serverKey.PublicKey().Bytes()),
					PreSharedKey: peer.PreSharedKey, Endpoint: "127.0.0.1:" + port,
					AllowedIps: []string{"10.0.0.1/32"},
				}},
			}), conn.NewDefaultBind()); err != nil {
				t.Fatal(err)
			}
			newConnection, err := newClientTun.DialContextTCPAddrPort(ctx, netip.MustParseAddrPort("10.0.0.1:9999"))
			if err != nil {
				t.Fatal(err)
			}
			echo(newConnection, "new peer works without restarting the core")
			_ = newConnection.Close()
			_ = newClientTun.Close()
			echo(connection, "old session survives a new user's first connection")
		}
		if err := s.RemoveUser(ctx, user.Email); err != nil {
			t.Fatal(err)
		}
		echo(connection, fmt.Sprintf("same encrypted TCP connection after remove %d", i))
	}
	if serverTun.(*gvisorNet).device != serverDevice || serverDevice.LookupPeer(key) != original {
		t.Fatal("established WireGuard peer or its device was replaced")
	}
}
