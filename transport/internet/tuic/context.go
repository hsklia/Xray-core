package tuic

import (
	"context"
	"crypto/tls"
	"time"

	"github.com/xtls/xray-core/common/protocol"
)

type Authenticator interface {
	Authenticate(ctx context.Context, uuid [16]byte, token []byte, tlsState tls.ConnectionState) (*protocol.MemoryUser, bool)
}

type authenticatorContextKey struct{}
type settingsContextKey struct{}
type clientSettingsContextKey struct{}
type requireDatagramContextKey struct{}

type ServerSettings struct {
	CongestionControl string
	AuthTimeout       time.Duration
	ZeroRTTHandshake  bool
	Heartbeat         time.Duration
	UDPTimeout        time.Duration
}

// ClientSettings carries the outbound's credentials and tuning from the proxy
// down to the transport dialer, mirroring how the inbound passes its
// Authenticator up. Credentials live in the proxy's `settings`, not in
// streamSettings, so the transport cannot read them any other way.
type ClientSettings struct {
	UUID              [16]byte
	Password          string
	CongestionControl string
	UDPStream         bool
	ZeroRTTHandshake  bool
	Heartbeat         time.Duration
}

func ContextWithClientSettings(ctx context.Context, settings ClientSettings) context.Context {
	return context.WithValue(ctx, clientSettingsContextKey{}, settings)
}

func ClientSettingsFromContext(ctx context.Context) (ClientSettings, bool) {
	settings, ok := ctx.Value(clientSettingsContextKey{}).(ClientSettings)
	return settings, ok
}

// ContextWithRequireDatagram marks a dial as needing the UDP association rather
// than a Connect stream. Same idiom as hysteria's ContextWithRequireDatagram.
func ContextWithRequireDatagram(ctx context.Context, udp bool) context.Context {
	if !udp {
		return ctx
	}
	return context.WithValue(ctx, requireDatagramContextKey{}, struct{}{})
}

func RequireDatagramFromContext(ctx context.Context) bool {
	_, ok := ctx.Value(requireDatagramContextKey{}).(struct{})
	return ok
}

func ContextWithAuthenticator(ctx context.Context, authenticator Authenticator) context.Context {
	return context.WithValue(ctx, authenticatorContextKey{}, authenticator)
}

func AuthenticatorFromContext(ctx context.Context) Authenticator {
	authenticator, _ := ctx.Value(authenticatorContextKey{}).(Authenticator)
	return authenticator
}

func ContextWithServerSettings(ctx context.Context, settings ServerSettings) context.Context {
	return context.WithValue(ctx, settingsContextKey{}, settings)
}

func ServerSettingsFromContext(ctx context.Context) ServerSettings {
	settings, _ := ctx.Value(settingsContextKey{}).(ServerSettings)
	return settings
}
