package tuic

import (
	"context"
	"crypto/tls"
	"sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
)

func GetTLSConfigFromStreamSettings(streamSettings *internet.MemoryStreamConfig, destination net.Destination) (*tls.Config, error) {
	if streamSettings == nil {
		return nil, errors.New("streamSettings is nil")
	}
	if streamSettings.ProtocolName != protocolName {
		return nil, errors.New("streamSettings network must be '", protocolName, "', got: ", streamSettings.ProtocolName)
	}

	tlsConfig := xtls.ConfigFromStreamSettings(streamSettings)
	if tlsConfig == nil {
		return &tls.Config{
			ServerName: destination.Address.String(),
			NextProtos: []string{"h3"},
			MinVersion: tls.VersionTLS13,
		}, nil
	}
	return tlsConfig.GetTLSConfig(xtls.WithNextProto("h3"), xtls.WithDestination(destination)), nil
}

// clientKey identifies one authenticated QUIC connection. Everything that
// changes the connection or its credentials belongs in the key, so two outbounds
// with different accounts never share a tunnel.
type clientKey struct {
	destination string
	settings    ClientSettings
}

var (
	clientCacheAccess sync.Mutex
	clientCache       = make(map[clientKey]*Client)
)

func getClient(destination net.Destination, tlsConfig *tls.Config, socketConfig *internet.SocketConfig, settings ClientSettings) *Client {
	key := clientKey{destination: destination.NetAddr(), settings: settings}
	clientCacheAccess.Lock()
	defer clientCacheAccess.Unlock()
	if client, ok := clientCache[key]; ok {
		return client
	}
	client := NewClient(destination, tlsConfig, socketConfig, settings)
	clientCache[key] = client
	return client
}

func dialTUIC(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	settings, ok := ClientSettingsFromContext(ctx)
	if !ok {
		return nil, errors.New(`the "tuic" transport is only usable by a TUIC outbound (no client settings in context)`)
	}

	tlsConfig, err := GetTLSConfigFromStreamSettings(streamSettings, dest)
	if err != nil {
		return nil, err
	}

	var socketConfig *internet.SocketConfig
	if streamSettings != nil {
		socketConfig = streamSettings.SocketSettings
	}
	client := getClient(dest, tlsConfig, socketConfig, settings)

	if RequireDatagramFromContext(ctx) {
		return client.OpenPacketConn(ctx)
	}
	return client.OpenStream(ctx)
}

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, dialTUIC))
}
