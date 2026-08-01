package tuic

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	stdnet "net"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apernet/quic-go"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/hysteria/congestion"
	"github.com/xtls/xray-core/transport/internet/hysteria/congestion/bbr"
	"github.com/xtls/xray-core/transport/internet/tuic/congestion/reno"
)

// Client owns one authenticated QUIC connection to a TUIC server and multiplexes
// every Connect stream and UDP association over it, redialing when it dies.
type Client struct {
	destination  net.Destination
	tlsConfig    *tls.Config
	socketConfig *internet.SocketConfig
	settings     ClientSettings

	access sync.Mutex
	conn   *clientConnection
}

func NewClient(destination net.Destination, tlsConfig *tls.Config, socketConfig *internet.SocketConfig, settings ClientSettings) *Client {
	if settings.Heartbeat <= 0 {
		settings.Heartbeat = 10 * time.Second
	}
	return &Client{
		destination:  destination,
		tlsConfig:    tlsConfig,
		socketConfig: socketConfig,
		settings:     settings,
	}
}

type clientConnection struct {
	quicConn   *quic.Conn
	rawConn    io.Closer
	ctx        context.Context
	cancel     context.CancelCauseFunc
	udpAccess  sync.RWMutex
	udpConnMap map[uint16]*udpPacketConn
	sessionID  atomic.Uint32
	closeOnce  sync.Once
}

func (c *clientConnection) closeWithError(err error) {
	c.closeOnce.Do(func() {
		c.cancel(err)
		_ = c.quicConn.CloseWithError(0, "")
		if c.rawConn != nil {
			_ = c.rawConn.Close()
		}
	})
}

func (c *clientConnection) alive() bool {
	select {
	case <-c.ctx.Done():
		return false
	default:
		return true
	}
}

// OpenStream returns an authenticated TUIC Connect stream. The caller writes the
// [version, command, address] header itself, the same split the server assumes.
func (c *Client) OpenStream(ctx context.Context) (stdnet.Conn, error) {
	conn, err := c.connection(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := conn.quicConn.OpenStreamSync(ctx)
	if err != nil {
		conn.closeWithError(err)
		return nil, errors.New("failed to open TUIC stream").Base(err)
	}
	return &streamConn{
		Stream: stream,
		local:  conn.quicConn.LocalAddr(),
		remote: conn.quicConn.RemoteAddr(),
	}, nil
}

// OpenPacketConn allocates a UDP association on the shared connection.
func (c *Client) OpenPacketConn(ctx context.Context) (PacketConn, error) {
	conn, err := c.connection(ctx)
	if err != nil {
		return nil, err
	}
	sessionID := uint16(conn.sessionID.Add(1))
	packetConn := newUDPPacketConn(conn.ctx, conn.quicConn, c.settings.UDPStream, false, nil, func() {
		conn.udpAccess.Lock()
		delete(conn.udpConnMap, sessionID)
		conn.udpAccess.Unlock()
	})
	packetConn.sessionID = sessionID
	conn.udpAccess.Lock()
	conn.udpConnMap[sessionID] = packetConn
	conn.udpAccess.Unlock()
	return packetConn, nil
}

func (c *Client) Close() error {
	c.access.Lock()
	conn := c.conn
	c.conn = nil
	c.access.Unlock()
	if conn != nil {
		conn.closeWithError(stdnet.ErrClosed)
	}
	return nil
}

func (c *Client) connection(ctx context.Context) (*clientConnection, error) {
	c.access.Lock()
	defer c.access.Unlock()
	if c.conn != nil && c.conn.alive() {
		return c.conn, nil
	}
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	c.conn = conn
	return conn, nil
}

func (c *Client) dial(ctx context.Context) (*clientConnection, error) {
	// The destination reaches us as TCP so that internet.Dial selects this
	// transport; the wire underneath QUIC is of course UDP.
	udpDestination := c.destination
	udpDestination.Network = net.Network_UDP

	raw, err := internet.DialSystem(ctx, udpDestination, c.socketConfig)
	if err != nil {
		return nil, errors.New("failed to dial TUIC server").Base(err)
	}

	var (
		packetConn stdnet.PacketConn
		remote     stdnet.Addr
	)
	switch typed := raw.(type) {
	case *internet.PacketConnWrapper:
		packetConn = typed.PacketConn
		remote = typed.RemoteAddr()
	case *net.UDPConn:
		packetConn = typed
		remote = typed.RemoteAddr()
	default:
		_ = raw.Close()
		return nil, errors.New("TUIC requires a UDP connection, got ", reflect.TypeOf(typed))
	}

	quicConfig := &quic.Config{
		DisablePathMTUDiscovery:        !(runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "android" || runtime.GOOS == "darwin"),
		EnableDatagrams:                true,
		MaxIncomingStreams:             1 << 60,
		MaxIncomingUniStreams:          1 << 60,
		MaxDatagramFrameSize:           1200,
		AssumePeerMaxDatagramFrameSize: 1200,
		DisablePathManager:             true,
	}

	var quicConn *quic.Conn
	if c.settings.ZeroRTTHandshake {
		quicConn, err = quic.DialEarly(ctx, packetConn, remote, c.tlsConfig, quicConfig)
	} else {
		quicConn, err = quic.Dial(ctx, packetConn, remote, c.tlsConfig, quicConfig)
	}
	if err != nil {
		_ = raw.Close()
		return nil, errors.New("failed to establish TUIC QUIC connection").Base(err)
	}

	c.setCongestion(quicConn)

	connCtx, cancel := context.WithCancelCause(context.Background())
	conn := &clientConnection{
		quicConn:   quicConn,
		rawConn:    raw,
		ctx:        connCtx,
		cancel:     cancel,
		udpConnMap: make(map[uint16]*udpPacketConn),
	}

	if err := c.authenticate(quicConn); err != nil {
		conn.closeWithError(err)
		return nil, errors.New("TUIC authentication failed").Base(err)
	}

	// Both carriers are always accepted on the read side; which one the server
	// picks follows the association, not a client setting.
	go c.loopUniStreams(conn)
	go c.loopMessages(conn)
	go c.loopHeartbeats(conn)

	errors.LogInfo(ctx, "TUIC connected to ", c.destination)
	return conn, nil
}

func (c *Client) setCongestion(conn *quic.Conn) {
	switch c.settings.CongestionControl {
	case "bbr":
		congestion.UseBBR(conn, bbr.ProfileStandard)
	case "new_reno":
		conn.SetCongestionControl(reno.NewSender(bbr.GetInitialPacketSize(conn.RemoteAddr())))
	default:
		// "cubic": quic-go's built-in default.
	}
}

func (c *Client) authenticate(quicConn *quic.Conn) error {
	stream, err := quicConn.OpenUniStream()
	if err != nil {
		return errors.New("failed to open TUIC auth stream").Base(err)
	}
	defer stream.Close()

	tlsState := quicConn.ConnectionState().TLS
	token, err := tlsState.ExportKeyingMaterial(string(c.settings.UUID[:]), []byte(c.settings.Password), 32)
	if err != nil {
		return errors.New("failed to export keying material").Base(err)
	}

	request := bytes.NewBuffer(make([]byte, 0, authenticateLen))
	request.WriteByte(tuicVersion)
	request.WriteByte(commandAuthenticate)
	request.Write(c.settings.UUID[:])
	request.Write(token)
	_, err = stream.Write(request.Bytes())
	return err
}

func (c *Client) loopHeartbeats(conn *clientConnection) {
	ticker := time.NewTicker(c.settings.Heartbeat)
	defer ticker.Stop()
	for {
		select {
		case <-conn.ctx.Done():
			return
		case <-ticker.C:
			if err := conn.quicConn.SendDatagram([]byte{tuicVersion, commandHeartbeat}); err != nil {
				conn.closeWithError(errors.New("send heartbeat").Base(err))
				return
			}
		}
	}
}

func (c *Client) loopMessages(conn *clientConnection) {
	for {
		data, err := conn.quicConn.ReceiveDatagram(conn.ctx)
		if err != nil {
			conn.closeWithError(err)
			return
		}
		if len(data) < 2 || data[0] != tuicVersion {
			continue
		}
		switch data[1] {
		case commandPacket:
			message := new(udpMessage)
			if err := decodeUDPMessage(message, data[2:]); err != nil {
				continue
			}
			c.deliver(conn, message)
		case commandHeartbeat:
		}
	}
}

func (c *Client) loopUniStreams(conn *clientConnection) {
	for {
		stream, err := conn.quicConn.AcceptUniStream(conn.ctx)
		if err != nil {
			return
		}
		go func(stream *quic.ReceiveStream) {
			defer stream.CancelRead(0)
			header := make([]byte, 2)
			if _, err := io.ReadFull(stream, header); err != nil {
				return
			}
			if header[0] != tuicVersion || header[1] != commandPacket {
				return
			}
			message := new(udpMessage)
			if err := readUDPMessage(message, stream); err != nil {
				return
			}
			c.deliver(conn, message)
		}(stream)
	}
}

func (c *Client) deliver(conn *clientConnection, message *udpMessage) {
	conn.udpAccess.RLock()
	packetConn := conn.udpConnMap[message.sessionID]
	conn.udpAccess.RUnlock()
	if packetConn == nil {
		return
	}
	packetConn.inputPacket(message)
}
