package naive

import (
	"context"
	gotls "crypto/tls"
	"net/http"
	"slices"
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

// Listener owns the sockets a naive inbound listens on. It is deliberately dumb
// about the naive protocol itself: TCP conns go straight to the inbound, and
// every HTTP/3 request is handed over as a conn so that the very same handler
// in proxy/naive serves h1, h2 and h3.
type Listener struct {
	ctx     context.Context
	addConn internet.ConnHandler

	tcpListener net.Listener

	pktConn    net.PacketConn
	h3listener *quic.EarlyListener
	h3server   *http3.Server
}

type h3Handler struct {
	addConn internet.ConnHandler
	local   net.Addr
}

func (h *h3Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	conn := newRequestConn(w, r, h.local)
	h.addConn(conn)
	// The stream worker closes the conn when Process() returns; only then may
	// this handler return, because that is what ends the HTTP/3 response.
	<-conn.Wait()
}

// tcpTLSConfig strips h3 from the negotiated ALPN set so that one tlsSettings
// block can drive both wires of a "tcp,udp" inbound.
func tcpTLSConfig(c *gotls.Config) *gotls.Config {
	if c == nil {
		return nil
	}
	protos := make([]string, 0, len(c.NextProtos))
	for _, p := range c.NextProtos {
		if p != "h3" {
			protos = append(protos, p)
		}
	}
	if len(protos) == 0 {
		protos = []string{"h2", "http/1.1"}
	}
	c.NextProtos = protos
	return c
}

func (l *Listener) keepAcceptingTCP() {
	for {
		conn, err := l.tcpListener.Accept()
		if err != nil {
			errors.LogInfoInner(l.ctx, err, "naive TCP listener closed")
			return
		}
		l.addConn(conn.(stat.Connection))
	}
}

func (l *Listener) keepAcceptingQUIC(quicParams *internet.QuicParams) {
	for {
		conn, err := l.h3listener.Accept(context.Background())
		if err != nil {
			errors.LogInfoInner(l.ctx, err, "naive QUIC listener closed")
			return
		}

		switch quicParams.Congestion {
		case "force-brutal":
			congestion.UseBrutal(conn, quicParams.BrutalUp)
		case "reno":
		default:
			congestion.UseBBR(conn, bbr.Profile(quicParams.BbrProfile))
		}

		go func(conn *quic.Conn) {
			if err := l.h3server.ServeQUICConn(conn); err != nil {
				errors.LogDebugInner(l.ctx, err, "naive HTTP/3 connection ended")
			}
			_ = conn.CloseWithError(closeErrCodeOK, "")
		}(conn)
	}
}

// Listen implements internet.ListenFunc.
func Listen(ctx context.Context, address net.Address, port net.Port, streamSettings *internet.MemoryStreamConfig, addConn internet.ConnHandler) (internet.Listener, error) {
	config, _ := streamSettings.ProtocolSettings.(*Config)
	mode := config.mode()

	l := &Listener{
		ctx:     ctx,
		addConn: addConn,
	}

	tlsSettings := tls.ConfigFromStreamSettings(streamSettings)

	if mode.tcp {
		listener, err := internet.ListenSystem(ctx, &net.TCPAddr{
			IP:   address.IP(),
			Port: int(port),
		}, streamSettings.SocketSettings)
		if err != nil {
			return nil, errors.New("failed to listen TCP for naive on ", address, ":", port).Base(err)
		}
		if streamSettings.TcpmaskManager != nil {
			listener, _ = streamSettings.TcpmaskManager.WrapListener(listener)
		}
		if tlsSettings != nil {
			if tlsConfig := tcpTLSConfig(tlsSettings.GetTLSConfig()); tlsConfig != nil {
				listener = gotls.NewListener(listener, tlsConfig)
			}
		}
		l.tcpListener = listener
		errors.LogInfo(ctx, "listening TCP for naive (h1/h2) on ", address, ":", port)
		go l.keepAcceptingTCP()
	}

	// QUIC has no cleartext mode. Rather than refuse the whole inbound, drop the
	// h3 wire, since serving h2c behind a TLS-terminating front proxy is a real
	// deployment and there is nothing wrong with it.
	if mode.udp && tlsSettings == nil {
		if !mode.tcp {
			return nil, errors.New("naive over HTTP/3 requires TLS")
		}
		errors.LogWarning(ctx, "naive: no TLS configured, serving HTTP/2 only (HTTP/3 needs TLS)")
		mode.udp = false
	}

	if mode.udp {
		raw, err := internet.ListenSystemPacket(context.Background(), &net.UDPAddr{
			IP:   address.IP(),
			Port: int(port),
		}, streamSettings.SocketSettings)
		if err != nil {
			l.Close()
			return nil, errors.New("failed to listen UDP for naive on ", address, ":", port).Base(err)
		}
		l.pktConn = raw
		if streamSettings.UdpmaskManager != nil {
			masked, err := streamSettings.UdpmaskManager.WrapPacketConnServer(raw)
			if err != nil {
				l.Close()
				return nil, errors.New("mask err").Base(err)
			}
			l.pktConn = masked
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
			MaxIncomingStreams:             quicParams.MaxIncomingStreams,
			DisablePathMTUDiscovery:        quicParams.DisablePathMtuDiscovery,
		}
		if quicConfig.MaxIdleTimeout == 0 {
			quicConfig.MaxIdleTimeout = 30 * time.Second
		}
		if quicConfig.MaxIncomingStreams == 0 {
			quicConfig.MaxIncomingStreams = 1024
		}

		h3TLS := tlsSettings.GetTLSConfig()
		if !slices.Contains(h3TLS.NextProtos, http3.NextProtoH3) {
			h3TLS.NextProtos = []string{http3.NextProtoH3}
		}

		l.h3listener, err = quic.ListenEarly(l.pktConn, h3TLS, quicConfig)
		if err != nil {
			l.Close()
			return nil, errors.New("failed to listen QUIC for naive on ", address, ":", port).Base(err)
		}
		l.h3server = &http3.Server{
			Handler: &h3Handler{addConn: addConn, local: l.h3listener.Addr()},
		}
		errors.LogInfo(ctx, "listening QUIC for naive (h3) on ", address, ":", port)
		go l.keepAcceptingQUIC(quicParams)
	}

	return l, nil
}

// Addr implements internet.Listener.
func (l *Listener) Addr() net.Addr {
	if l.tcpListener != nil {
		return l.tcpListener.Addr()
	}
	if l.h3listener != nil {
		return l.h3listener.Addr()
	}
	return nil
}

// Close implements internet.Listener.
func (l *Listener) Close() error {
	var err error
	if l.tcpListener != nil {
		err = l.tcpListener.Close()
	}
	if l.h3server != nil {
		if e := l.h3server.Close(); e != nil && err == nil {
			err = e
		}
	}
	if l.h3listener != nil {
		if e := l.h3listener.Close(); e != nil && err == nil {
			err = e
		}
	}
	if l.pktConn != nil {
		_ = l.pktConn.Close()
	}
	return err
}

func init() {
	common.Must(internet.RegisterTransportListener(protocolName, Listen))
}
