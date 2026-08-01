package naive

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/hysteria/congestion"
	"github.com/xtls/xray-core/transport/internet/hysteria/congestion/bbr"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

// ConnectRequest carries one naive CONNECT exchange across the proxy/transport
// boundary. The proxy owns the naive protocol (auth, padding, target), the
// transport owns the QUIC and HTTP/3 machinery, and this is the only thing they
// need to agree on.
type ConnectRequest struct {
	Authority string
	Header    http.Header

	// Filled in by the dialer once the response headers arrive.
	StatusCode int
	Response   http.Header
}

type connectRequestKey struct{}

// ContextWithConnectRequest attaches a CONNECT exchange for the dialer to run.
func ContextWithConnectRequest(ctx context.Context, r *ConnectRequest) context.Context {
	return context.WithValue(ctx, connectRequestKey{}, r)
}

// ConnectRequestFromContext returns the CONNECT exchange, if any.
func ConnectRequestFromContext(ctx context.Context) *ConnectRequest {
	r, _ := ctx.Value(connectRequestKey{}).(*ConnectRequest)
	return r
}

type h3Session struct {
	quicConn *quic.Conn
	client   *http3.ClientConn
}

var (
	h3Mutex    sync.Mutex
	h3Sessions = make(map[string]*h3Session)
)

func sessionKey(dest net.Destination, serverName string) string {
	return dest.NetAddr() + "|" + serverName
}

func dialH3(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (*h3Session, error) {
	tlsSettings := tls.ConfigFromStreamSettings(streamSettings)
	if tlsSettings == nil {
		return nil, errors.New("naive over HTTP/3 requires TLS")
	}
	tlsConfig := tlsSettings.GetTLSConfig(tls.WithDestination(dest))
	if !slices.Contains(tlsConfig.NextProtos, http3.NextProtoH3) {
		tlsConfig.NextProtos = []string{http3.NextProtoH3}
	}

	key := sessionKey(dest, tlsConfig.ServerName)

	h3Mutex.Lock()
	defer h3Mutex.Unlock()

	if session := h3Sessions[key]; session != nil {
		select {
		case <-session.client.Context().Done():
			delete(h3Sessions, key)
		default:
			return session, nil
		}
	}

	// The proxy hands us a TCP destination (that is what a server address is),
	// but h3 rides QUIC, so the socket has to be a UDP one.
	udpDest := dest
	udpDest.Network = net.Network_UDP
	conn, err := internet.DialSystem(ctx, udpDest, streamSettings.SocketSettings)
	if err != nil {
		return nil, err
	}

	var packetConn net.PacketConn
	var udpAddr *net.UDPAddr
	switch c := conn.(type) {
	case *internet.PacketConnWrapper:
		packetConn = c.PacketConn
		udpAddr, err = net.ResolveUDPAddr("udp", c.Dest.String())
	case *net.UDPConn:
		packetConn = c
		udpAddr, err = net.ResolveUDPAddr("udp", c.RemoteAddr().String())
	default:
		packetConn = &internet.FakePacketConn{Conn: c}
		udpAddr, err = net.ResolveUDPAddr("udp", c.RemoteAddr().String())
	}
	if err != nil {
		conn.Close()
		return nil, err
	}

	if streamSettings.UdpmaskManager != nil {
		packetConn, err = streamSettings.UdpmaskManager.WrapPacketConnClient(packetConn)
		if err != nil {
			conn.Close()
			return nil, errors.New("mask err").Base(err)
		}
	}

	quicParams := streamSettings.QuicParams
	if quicParams == nil {
		quicParams = &internet.QuicParams{
			BbrProfile: string(bbr.ProfileStandard),
			UdpHop:     &internet.UdpHop{},
		}
	}
	quicConfig := &quic.Config{
		InitialStreamReceiveWindow:     quicParams.InitStreamReceiveWindow,
		MaxStreamReceiveWindow:         quicParams.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: quicParams.InitConnReceiveWindow,
		MaxConnectionReceiveWindow:     quicParams.MaxConnReceiveWindow,
		MaxIdleTimeout:                 time.Duration(quicParams.MaxIdleTimeout) * time.Second,
		DisablePathMTUDiscovery:        quicParams.DisablePathMtuDiscovery,
	}
	if quicConfig.MaxIdleTimeout == 0 {
		quicConfig.MaxIdleTimeout = 30 * time.Second
	}

	quicConn, err := quic.DialEarly(ctx, packetConn, udpAddr, tlsConfig, quicConfig)
	if err != nil {
		conn.Close()
		return nil, err
	}
	switch quicParams.Congestion {
	case "force-brutal":
		congestion.UseBrutal(quicConn, quicParams.BrutalUp)
	case "reno":
	default:
		congestion.UseBBR(quicConn, bbr.Profile(quicParams.BbrProfile))
	}

	session := &h3Session{
		quicConn: quicConn,
		client:   (&http3.Transport{}).NewClientConn(quicConn),
	}
	h3Sessions[key] = session
	return session, nil
}

// Dial implements internet.Dialer for the naive transport. It only serves the
// HTTP/3 wire; the HTTP/2 wire needs no transport of its own because it runs
// over the standard TLS stream, which is also how it inherits uTLS.
func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	request := ConnectRequestFromContext(ctx)
	if request == nil {
		return nil, errors.New(`the "naive" transport can only be used by a naive outbound`)
	}

	session, err := dialH3(ctx, dest, streamSettings)
	if err != nil {
		return nil, err
	}

	stream, err := session.client.OpenRequestStream(ctx)
	if err != nil {
		h3Mutex.Lock()
		for k, v := range h3Sessions {
			if v == session {
				delete(h3Sessions, k)
			}
		}
		h3Mutex.Unlock()
		return nil, errors.New("naive: failed to open an HTTP/3 request stream").Base(err)
	}

	header := request.Header
	if header == nil {
		header = http.Header{}
	}
	// Proto must stay empty: quic-go reads a non-empty Proto on a CONNECT as a
	// request for Extended CONNECT (RFC 8441), which is a different exchange.
	httpRequest := (&http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: request.Authority},
		Host:   request.Authority,
		Header: header,
	}).WithContext(ctx)

	if err := stream.SendRequestHeader(httpRequest); err != nil {
		stream.Close()
		return nil, errors.New("naive: failed to send CONNECT").Base(err)
	}
	response, err := stream.ReadResponse()
	if err != nil {
		stream.Close()
		return nil, errors.New("naive: failed to read the CONNECT response").Base(err)
	}
	request.StatusCode = response.StatusCode
	request.Response = response.Header

	return &streamConn{
		stream: stream,
		local:  session.quicConn.LocalAddr(),
		remote: session.quicConn.RemoteAddr(),
	}, nil
}

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
}
