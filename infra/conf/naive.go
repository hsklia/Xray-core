package conf

import (
	"context"
	"strings"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/naive"
	"github.com/xtls/xray-core/transport/internet"
	naivetransport "github.com/xtls/xray-core/transport/internet/naive"
	"google.golang.org/protobuf/proto"
)

// NaiveMasqueradeConfig is the masquerade site a naive inbound serves to
// anything that is not an authenticated CONNECT. Since naiveproxy v147 the
// client itself fetches "/" and the subresources it links to, so this is part of
// the protocol, not decoration.
type NaiveMasqueradeConfig struct {
	Type string `json:"type"`

	File string `json:"file"`

	Url         string `json:"url"`
	RewriteHost bool   `json:"rewriteHost"`
	Insecure    bool   `json:"insecure"`

	String     string            `json:"string"`
	Headers    map[string]string `json:"headers"`
	StatusCode int32             `json:"statusCode"`
}

func (c *NaiveMasqueradeConfig) Build() *naive.Masquerade {
	if c == nil {
		return nil
	}
	return &naive.Masquerade{
		Type:           c.Type,
		File:           c.File,
		Url:            c.Url,
		UrlRewriteHost: c.RewriteHost,
		UrlInsecure:    c.Insecure,
		Content:        c.String,
		Headers:        c.Headers,
		StatusCode:     c.StatusCode,
	}
}

type NaiveUserConfig struct {
	Email string `json:"email"`
	// Username is the Basic-auth username. Omitted or empty falls back to the
	// email, which is what every client saved before this field existed relies
	// on. The email remains the accounting identity in both cases.
	Username string `json:"username"`
	Password string `json:"password"`
	Level    uint32 `json:"level"`
}

type NaiveServerConfig struct {
	Clients    []*NaiveUserConfig     `json:"clients"`
	Network    string                 `json:"network"`
	Realm      string                 `json:"realm"`
	Masquerade *NaiveMasqueradeConfig `json:"masquerade"`
}

// Build implements Buildable.
func (c *NaiveServerConfig) Build() (proto.Message, error) {
	config := new(naive.ServerConfig)
	config.Network = c.Network
	config.Realm = c.Realm
	config.Masquerade = c.Masquerade.Build()

	// Degrade rather than fail, per account: a Build error makes Xray refuse the
	// ENTIRE config, so one malformed naive client would take down every other
	// inbound on the box. It arrives by import, restore or a panel bug and
	// detonates on a later unrelated restart when nobody is watching. Losing
	// this one account loudly beats losing the node.
	seen := make(map[string]bool, len(c.Clients))
	for _, user := range c.Clients {
		if user == nil {
			continue
		}
		// HTTP Basic splits the decoded credential on the first colon, so a
		// colon in the username can never be sent. The email is not checked: it
		// has always been usable as the Basic username, and rejecting one now
		// would break accounts that authenticate today.
		if strings.Contains(user.Username, ":") {
			errors.LogWarning(context.Background(), `naive: dropping client `, describeNaiveClient(user),
				`: "username" must not contain a colon, HTTP Basic cannot express it`)
			continue
		}
		basicUsername := user.Username
		if basicUsername == "" {
			basicUsername = user.Email
		}
		if basicUsername == "" {
			errors.LogWarning(context.Background(), `naive: dropping a client with neither "username" nor "email": one of them is the Basic auth username`)
			continue
		}
		if user.Password == "" {
			errors.LogWarning(context.Background(), `naive: dropping client `, describeNaiveClient(user), `: "password" is required`)
			continue
		}
		// Two accounts answering to one Basic username means the second is
		// unreachable and which one wins is map order, so neither is trustworthy.
		if seen[basicUsername] {
			errors.LogWarning(context.Background(), `naive: dropping client `, describeNaiveClient(user),
				`: Basic username `, basicUsername, ` is already taken by another client on this inbound`)
			continue
		}
		seen[basicUsername] = true

		config.Clients = append(config.Clients, &protocol.User{
			Email: user.Email,
			Level: user.Level,
			Account: serial.ToTypedMessage(&naive.Account{
				Password: user.Password,
				Username: user.Username,
			}),
		})
	}

	if len(config.Clients) == 0 {
		errors.LogWarning(context.Background(), `naive: inbound has no usable accounts and will answer every CONNECT with 407.`)
	}

	return config, nil
}

func describeNaiveClient(user *NaiveUserConfig) string {
	if user.Email != "" {
		return user.Email
	}
	if user.Username != "" {
		return user.Username
	}
	return "<no email>"
}

type NaiveClientConfig struct {
	Address *Address `json:"address"`
	Port    uint16   `json:"port"`
	Email   string   `json:"email"`
	// Username is what goes on the wire in the Basic credential. It falls back
	// to the email so links written before the field existed keep dialling.
	Username string `json:"username"`
	Password string `json:"password"`
	Level    uint32 `json:"level"`
	Network  string `json:"network"`
}

// Build implements Buildable.
func (c *NaiveClientConfig) Build() (proto.Message, error) {
	if c.Address == nil {
		return nil, errors.New("naive outbound needs an address")
	}
	// Unlike the inbound's client list there is nothing here to degrade to: an
	// outbound with no credential cannot dial anything, so this stays an error.
	if c.Username == "" && c.Email == "" {
		return nil, errors.New("naive outbound needs a username or an email, one of them is the Basic auth username")
	}
	if c.Password == "" {
		return nil, errors.New("naive outbound needs a password")
	}
	if strings.Contains(c.Username, ":") {
		return nil, errors.New("naive outbound username must not contain a colon, HTTP Basic cannot express it")
	}

	return &naive.ClientConfig{
		Network: c.Network,
		Server: &protocol.ServerEndpoint{
			Address: c.Address.Build(),
			Port:    uint32(c.Port),
			User: &protocol.User{
				Email: c.Email,
				Level: c.Level,
				Account: serial.ToTypedMessage(&naive.Account{
					Password: c.Password,
					Username: c.Username,
				}),
			},
		},
	}, nil
}

// NaiveTransportConfig selects which wires a naive listener owns. Configs do not
// need to set "naiveSettings": NormalizeNaiveInboundStream fills it in from
// settings.network, which is the single source of truth.
type NaiveTransportConfig struct {
	Network string `json:"network"`
}

// Build implements Buildable.
func (c *NaiveTransportConfig) Build() (proto.Message, error) {
	return &naivetransport.Config{Network: c.Network}, nil
}

// setNaiveTransport forces the naive transport onto a stream config and gives it
// the network mode from the proxy settings.
func setNaiveTransport(stream *internet.StreamConfig, network string) {
	stream.ProtocolName = "naive"
	settings := serial.ToTypedMessage(&naivetransport.Config{Network: network})
	for _, transportSettings := range stream.TransportSettings {
		if transportSettings.ProtocolName == "naive" {
			transportSettings.Settings = settings
			return
		}
	}
	stream.TransportSettings = append(stream.TransportSettings, &internet.TransportConfig{
		ProtocolName: "naive",
		Settings:     settings,
	})
}

// NormalizeNaiveInboundStream makes a naive inbound listen on the wires its own
// settings ask for.
//
// naive's transport is part of the protocol: "tcp" is HTTP/2 over TLS and "udp"
// is HTTP/3 over QUIC, and one inbound may serve both on the same port. That
// does not fit any stock Xray transport, so the sockets are owned by
// transport/internet/naive. Rather than make callers write the same network in
// two places (where a mismatch would silently bind the wrong wire, or none),
// settings.network is the single source of truth and this overrides whatever
// streamSettings.network said. No expressiveness is lost: REALITY cannot work
// with a naive client, which does a plain TLS handshake, and ws/grpc/xhttp are
// meaningless under a protocol that is defined as HTTP/2 or HTTP/3. TLS and
// sockopt are untouched.
func NormalizeNaiveInboundStream(rawConfig interface{}, receiver *proxyman.ReceiverConfig) {
	config, ok := rawConfig.(*NaiveServerConfig)
	if !ok || receiver == nil {
		return
	}
	if receiver.StreamSettings == nil {
		receiver.StreamSettings = &internet.StreamConfig{}
	}
	setNaiveTransport(receiver.StreamSettings, config.Network)
}

// NormalizeNaiveOutboundStream picks the wire a naive outbound dials on, from
// settings.network alone. HTTP/3 needs transport/internet/naive for its QUIC
// socket; HTTP/2 deliberately stays on the standard TLS stream, which is what
// gives it Xray's uTLS fingerprinting for free.
//
// Only "udp" on its own selects HTTP/3. A dialer opens one wire, so every other
// spelling resolves to HTTP/2 -- including "tcp,udp" and, because ParseNetwork
// reads an empty or unrecognised value as both, an omitted network too. That
// matches NewClient, which computes the same `udp && !tcp`.
//
// Both directions are forced, not just the h3 one. Leaving streamSettings on
// "naive" while asking for "tcp" would send the h2 dial through a transport that
// has no CONNECT exchange to run, and the outbound would fail on every dial.
func NormalizeNaiveOutboundStream(rawConfig interface{}, sender *proxyman.SenderConfig) {
	config, ok := rawConfig.(*NaiveClientConfig)
	if !ok || sender == nil {
		return
	}
	tcp, udp := naivetransport.ParseNetwork(config.Network)
	if udp && !tcp {
		if sender.StreamSettings == nil {
			sender.StreamSettings = &internet.StreamConfig{}
		}
		setNaiveTransport(sender.StreamSettings, config.Network)
		return
	}
	if sender.StreamSettings != nil && sender.StreamSettings.ProtocolName == "naive" {
		sender.StreamSettings.ProtocolName = "tcp"
	}
}
