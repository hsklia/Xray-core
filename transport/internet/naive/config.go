package naive

import (
	"strings"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/transport/internet"
)

const protocolName = "naive"

const (
	// closeErrCodeOK is HTTP/3's ErrCodeNoError.
	closeErrCodeOK = 0x100
)

// listenMode says which wires a naive listener owns. NaiveProxy speaks CONNECT
// over HTTP/2 (TLS/TCP) and over HTTP/3 (QUIC/UDP); a single inbound may serve
// both on the same port number.
type listenMode struct {
	tcp bool
	udp bool
}

// ParseNetwork turns the "tcp"/"udp"/"tcp,udp" spelling used by both the proxy
// settings and the transport settings into a mode. Empty, and anything it does
// not recognise, means BOTH rather than tcp: that is what a stock naiveproxy
// server offers, and it is the safe reading for a listener.
//
// A dialer cannot use both at once, so callers on the outbound side resolve
// "both" to HTTP/2 (see NewClient and NormalizeNaiveOutboundStream). HTTP/2 is
// the right tie-break: it is naiveproxy's own default scheme ("https://") and
// the wire that survives networks where UDP is blocked.
//
// MIRRORED in the panel, at Outbound.NaiveSettings.resolveNetwork in
// web/assets/js/model/outbound.js. Adding a UDP spelling here without adding it
// there is the case that bites: the panel reads the unknown value as "both",
// resolves it to tcp, and shows an HTTP/2 stream for a connection this core
// dials over HTTP/3. Adding a TCP spelling is harmless, since both sides land on
// HTTP/2 either way.
func ParseNetwork(s string) (tcp, udp bool) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return true, true
	}
	for _, part := range strings.Split(s, ",") {
		switch strings.TrimSpace(part) {
		case "tcp", "h2", "http2":
			tcp = true
		case "udp", "h3", "http3", "quic":
			udp = true
		}
	}
	if !tcp && !udp {
		return true, true
	}
	return tcp, udp
}

func (c *Config) mode() listenMode {
	var network string
	if c != nil {
		network = c.Network
	}
	tcp, udp := ParseNetwork(network)
	return listenMode{tcp: tcp, udp: udp}
}

func init() {
	common.Must(internet.RegisterProtocolConfigCreator(protocolName, func() interface{} {
		return new(Config)
	}))
}
