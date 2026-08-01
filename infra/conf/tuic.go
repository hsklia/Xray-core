package conf

import (
	"context"
	"encoding/json"

	"google.golang.org/protobuf/proto"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/tuic"
)

// TuicClientConfigEntry is a single account of a TUIC inbound.
type TuicClientConfigEntry struct {
	ID       string `json:"id"`
	Password string `json:"password"`
	Level    byte   `json:"level"`
	Email    string `json:"email"`
}

// TuicServerConfig is the inbound configuration for TUIC.
type TuicServerConfig struct {
	Clients           []*TuicClientConfigEntry `json:"clients"`
	CongestionControl string                   `json:"congestionControl"`
	AuthTimeout       uint32                   `json:"authTimeout"`
	ZeroRttHandshake  bool                     `json:"zeroRttHandshake"`
	Heartbeat         uint32                   `json:"heartbeat"`
	UdpTimeout        uint32                   `json:"udpTimeout"`

	// Upstream TUIC configs spell the account list "users". Bound only so the
	// mistake can be named in the log. It is deliberately NOT read as an alias:
	// the panel filters disabled/expired accounts out of settings["clients"]
	// (web/service/xray.go), so a config whose accounts live under "users" would
	// connect happily with quota, expiry and disable enforcement all switched
	// off. A dead inbound is far better than a silently unmetered one.
	LegacyUsers json.RawMessage `json:"users"`
}

// Build implements Buildable
func (c *TuicServerConfig) Build() (proto.Message, error) {
	// Degrade rather than fail: a Build error makes Xray refuse the ENTIRE
	// config, so one malformed tuic inbound would take down every other inbound
	// on the box. This arrives by import or restore from a panel that spells the
	// account list "users", and it detonates on a later unrelated restart when
	// nobody is watching. Losing this one inbound loudly beats losing the node.
	if len(c.Clients) == 0 && len(c.LegacyUsers) > 0 {
		errors.LogWarning(context.Background(), `TUIC: ignoring "users": accounts belong in "clients". `,
			`This inbound has NO accounts and will reject every connection until it is fixed.`)
	}

	congestionControl := normalizeTuicCongestionControl(c.CongestionControl)

	config := &tuic.ServerConfig{
		Users:             make([]*protocol.User, 0, len(c.Clients)),
		CongestionControl: congestionControl,
		AuthTimeout:       c.AuthTimeout,
		ZeroRttHandshake:  c.ZeroRttHandshake,
		Heartbeat:         c.Heartbeat,
		UdpTimeout:        c.UdpTimeout,
	}

	if config.AuthTimeout == 0 {
		config.AuthTimeout = 3
	}
	if config.Heartbeat == 0 {
		config.Heartbeat = 10
	}
	if config.UdpTimeout == 0 {
		config.UdpTimeout = 60
	}

	for _, client := range c.Clients {
		if client == nil {
			continue
		}
		// Same reasoning, per account: drop the bad one, keep the inbound. An
		// empty password is also a real hole, since the auth token derives from
		// it and anyone who learns the UUID could then connect, so dropping is
		// both the graceful and the safe answer.
		if client.ID == "" {
			errors.LogWarning(context.Background(), `TUIC: dropping client `, describeTuicClient(client), `: "id" is required`)
			continue
		}
		if client.Password == "" {
			errors.LogWarning(context.Background(), `TUIC: dropping client `, describeTuicClient(client), `: "password" is required`)
			continue
		}

		account := &tuic.Account{
			Uuid:     client.ID,
			Password: client.Password,
		}

		config.Users = append(config.Users, &protocol.User{
			Level:   uint32(client.Level),
			Email:   client.Email,
			Account: serial.ToTypedMessage(account),
		})
	}

	if len(config.Users) == 0 {
		errors.LogWarning(context.Background(), `TUIC: inbound has no usable accounts and will reject every connection.`)
	}

	return config, nil
}

func describeTuicClient(client *TuicClientConfigEntry) string {
	if client.Email != "" {
		return client.Email
	}
	if client.ID != "" {
		return client.ID
	}
	return "<no email>"
}

// TuicServerTarget is the configuration of a single TUIC server for an outbound.
type TuicServerTarget struct {
	Address  *Address `json:"address"`
	Port     uint16   `json:"port"`
	Level    byte     `json:"level"`
	Email    string   `json:"email"`
	ID       string   `json:"id"`
	Password string   `json:"password"`
}

// TuicClientConfig is the outbound configuration for TUIC.
type TuicClientConfig struct {
	Address           *Address            `json:"address"`
	Port              uint16              `json:"port"`
	Level             byte                `json:"level"`
	Email             string              `json:"email"`
	ID                string              `json:"id"`
	Password          string              `json:"password"`
	Servers           []*TuicServerTarget `json:"servers"`
	CongestionControl string              `json:"congestionControl"`
	UDPRelayMode      string              `json:"udpRelayMode"`
	UdpStream         bool                `json:"udpStream"`
	ZeroRttHandshake  bool                `json:"zeroRttHandshake"`
	Heartbeat         uint32              `json:"heartbeat"`
}

// Build implements Buildable
func (c *TuicClientConfig) Build() (proto.Message, error) {
	if c.Address != nil {
		c.Servers = []*TuicServerTarget{
			{
				Address:  c.Address,
				Port:     c.Port,
				Level:    c.Level,
				Email:    c.Email,
				ID:       c.ID,
				Password: c.Password,
			},
		}
	}

	if len(c.Servers) == 0 {
		return nil, errors.New("TUIC: no server configured")
	}
	if len(c.Servers) > 1 {
		return nil, errors.New("TUIC: multiple servers not supported, use multiple outbounds instead")
	}

	congestionControl := normalizeTuicCongestionControl(c.CongestionControl)

	udpStream := c.UdpStream
	switch c.UDPRelayMode {
	case "":
	case "native":
		udpStream = false
	case "quic":
		udpStream = true
	default:
		errors.LogWarning(context.Background(), `TUIC: unknown udpRelayMode "`, c.UDPRelayMode,
			`" (expected "native" or "quic"), falling back to "native"`)
		udpStream = false
	}

	config := &tuic.ClientConfig{
		CongestionControl: congestionControl,
		UdpStream:         udpStream,
		ZeroRttHandshake:  c.ZeroRttHandshake,
		Heartbeat:         c.Heartbeat,
	}
	if config.Heartbeat == 0 {
		config.Heartbeat = 10
	}

	server := c.Servers[0]
	if server.Address == nil {
		return nil, errors.New("TUIC: server address is not set")
	}
	if server.Port == 0 {
		return nil, errors.New("TUIC: invalid server port")
	}
	if server.ID == "" {
		return nil, errors.New("TUIC: id is not specified")
	}
	if server.Password == "" {
		return nil, errors.New("TUIC: password is not specified")
	}

	config.Server = append(config.Server, &protocol.ServerEndpoint{
		Address: server.Address.Build(),
		Port:    uint32(server.Port),
		User: &protocol.User{
			Level: uint32(server.Level),
			Email: server.Email,
			Account: serial.ToTypedMessage(&tuic.Account{
				Uuid:     server.ID,
				Password: server.Password,
			}),
		},
	})

	return config, nil
}

// normalizeTuicCongestionControl names an unknown algorithm instead of letting
// it fall back to the QUIC default in silence, which is how "new_reno" managed
// to run Cubic for so long. It warns rather than erroring because a whole node
// should not go down over a tuning knob that has a perfectly good default, and
// because names valid in other TUIC implementations (bbr2, bbr_meta_v1) reach us
// through imported configs.
func normalizeTuicCongestionControl(name string) string {
	switch name {
	case "":
		return "cubic"
	case "cubic", "new_reno", "bbr":
		return name
	default:
		errors.LogWarning(context.Background(), `TUIC: unknown congestion control algorithm "`, name,
			`" (expected "cubic", "new_reno" or "bbr"), falling back to "cubic"`)
		return "cubic"
	}
}
