package tuic

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	stderrors "errors"
	"io"
	stdnet "net"
	"runtime"
	"sync"
	"time"

	"github.com/apernet/quic-go"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/hysteria/congestion"
	"github.com/xtls/xray-core/transport/internet/hysteria/congestion/bbr"
	"github.com/xtls/xray-core/transport/internet/tuic/congestion/reno"
)

type serverOptions struct {
	Context           context.Context
	TLSConfig         *tls.Config
	CongestionControl string
	AuthTimeout       time.Duration
	ZeroRTTHandshake  bool
	Heartbeat         time.Duration
	UDPTimeout        time.Duration
	Authenticator     Authenticator
	Handler           internet.ConnHandler
	LocalAddr         stdnet.Addr
}

type serverService struct {
	ctx               context.Context
	tlsConfig         *tls.Config
	quicConfig        *quic.Config
	congestionControl string
	authTimeout       time.Duration
	heartbeat         time.Duration
	udpTimeout        time.Duration
	authenticator     Authenticator
	handler           internet.ConnHandler
	localAddr         stdnet.Addr
	listener          io.Closer
	tr                *quic.Transport
}

func newServerService(options serverOptions) (*serverService, error) {
	if options.AuthTimeout == 0 {
		options.AuthTimeout = 3 * time.Second
	}
	if options.Heartbeat == 0 {
		options.Heartbeat = 10 * time.Second
	}
	if options.UDPTimeout == 0 {
		options.UDPTimeout = 60 * time.Second
	}
	switch options.CongestionControl {
	case "":
		options.CongestionControl = "cubic"
	case "cubic", "new_reno", "bbr":
	default:
		return nil, errors.New("unknown congestion control algorithm: ", options.CongestionControl)
	}
	return &serverService{
		ctx:       options.Context,
		tlsConfig: options.TLSConfig,
		quicConfig: &quic.Config{
			DisablePathMTUDiscovery:        !(runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "android" || runtime.GOOS == "darwin"),
			EnableDatagrams:                true,
			Allow0RTT:                      options.ZeroRTTHandshake,
			MaxIncomingStreams:             1 << 60,
			MaxIncomingUniStreams:          1 << 60,
			MaxDatagramFrameSize:           1200,
			AssumePeerMaxDatagramFrameSize: 1200,
			DisablePathManager:             true,
		},
		congestionControl: options.CongestionControl,
		authTimeout:       options.AuthTimeout,
		heartbeat:         options.Heartbeat,
		udpTimeout:        options.UDPTimeout,
		authenticator:     options.Authenticator,
		handler:           options.Handler,
		localAddr:         options.LocalAddr,
	}, nil
}

func (s *serverService) Start(conn stdnet.PacketConn) error {
	s.tr = &quic.Transport{Conn: conn}
	var listener interface {
		Accept(context.Context) (*quic.Conn, error)
		Close() error
	}
	var err error
	if s.quicConfig.Allow0RTT {
		listener, err = s.tr.ListenEarly(s.tlsConfig, s.quicConfig)
	} else {
		listener, err = s.tr.Listen(s.tlsConfig, s.quicConfig)
	}
	if err != nil {
		return err
	}
	s.listener = listener
	go s.acceptLoop(listener)
	return nil
}

func (s *serverService) CloseWithError() error {
	var errs []error
	if s.listener != nil {
		errs = append(errs, s.listener.Close())
	}
	if s.tr != nil {
		errs = append(errs, s.tr.Close())
	}
	return stderrors.Join(errs...)
}

func (s *serverService) acceptLoop(listener interface {
	Accept(context.Context) (*quic.Conn, error)
}) {
	for {
		conn, err := listener.Accept(s.ctx)
		if err != nil {
			if !stderrors.Is(err, quic.ErrServerClosed) && !stderrors.Is(err, context.Canceled) {
				errors.LogWarning(s.ctx, "TUIC accept error: ", err)
			}
			return
		}
		errors.LogDebug(s.ctx, "TUIC accepted QUIC connection from ", conn.RemoteAddr())
		go s.handleConnection(conn)
	}
}

func (s *serverService) handleConnection(conn *quic.Conn) {
	s.setCongestion(conn)
	session := &serverSession{
		serverService: s,
		ctx:           s.ctx,
		quicConn:      conn,
		connDone:      make(chan struct{}),
		authDone:      make(chan struct{}),
		udpConnMap:    make(map[uint16]*udpPacketConn),
	}
	errors.LogDebug(s.ctx, "TUIC starting session for ", conn.RemoteAddr())
	session.handle()
}

func (s *serverService) setCongestion(conn *quic.Conn) {
	errors.LogDebug(s.ctx, "TUIC installing congestion control '", s.congestionControl, "' for ", conn.RemoteAddr())
	switch s.congestionControl {
	case "bbr":
		congestion.UseBBR(conn, bbr.ProfileStandard)
	case "new_reno":
		// quic-go's default sender is CUBIC; New Reno is only reachable through
		// SetCongestionControl. Leaving this case out is what made the option a
		// silent no-op.
		conn.SetCongestionControl(reno.NewSender(bbr.GetInitialPacketSize(conn.RemoteAddr())))
	default:
		// "cubic": quic-go's built-in default, nothing to install.
	}
}

type serverSession struct {
	*serverService
	ctx           context.Context
	quicConn      *quic.Conn
	connAccess    sync.Mutex
	connDone      chan struct{}
	connErr       error
	authAccess    sync.Mutex
	authDone      chan struct{}
	authUser      *protocol.MemoryUser
	udpAccess     sync.RWMutex
	udpConnMap    map[uint16]*udpPacketConn
	pendingAccess sync.Mutex
	pendingTasks  []func() error
}

func (s *serverSession) handle() {
	go s.loopUniStreams()
	go s.loopStreams()
	go s.loopMessages()
	go s.handleAuthTimeout()
}

func (s *serverSession) loopUniStreams() {
	for {
		stream, err := s.quicConn.AcceptUniStream(s.ctx)
		if err != nil {
			return
		}
		go func() {
			if err := s.handleUniStream(stream); err != nil {
				s.closeWithError(errors.New("handle uni stream").Base(err))
			}
		}()
	}
}

func (s *serverSession) handleUniStream(stream *quic.ReceiveStream) error {
	// Ownership of the read side moves to the queued task when the command
	// arrives before authentication, so the cancel is conditional.
	cancelRead := true
	defer func() {
		if cancelRead {
			stream.CancelRead(0)
		}
	}()
	buffer := make([]byte, 2)
	if _, err := io.ReadFull(stream, buffer); err != nil {
		return err
	}
	if buffer[0] != tuicVersion {
		return errors.New("unknown version ", buffer[0])
	}
	switch buffer[1] {
	case commandAuthenticate:
		authPayload := make([]byte, authenticateLen-2)
		if _, err := io.ReadFull(stream, authPayload); err != nil {
			return err
		}
		var userUUID [16]byte
		copy(userUUID[:], authPayload[:16])
		if s.authenticator == nil {
			return errors.New("missing TUIC authenticator")
		}
		user, ok := s.authenticator.Authenticate(s.ctx, userUUID, authPayload[16:48], s.quicConn.ConnectionState().TLS)
		if !ok {
			return errors.New("token mismatch")
		}
		s.authAccess.Lock()
		defer s.authAccess.Unlock()
		select {
		case <-s.authDone:
			return errors.New("multiple authentication requests")
		default:
		}
		s.authUser = user
		close(s.authDone)
		errors.LogDebug(s.ctx, "TUIC authentication succeeded for ", s.quicConn.RemoteAddr(), " user: ", user.Email)
		go s.resumePendingTasks()
		go s.loopHeartbeats()
		return nil
	case commandPacket, commandDissociate:
		if s.authReady() {
			return s.handlePendingUniStream(stream, buffer)
		}
		errors.LogDebug(s.ctx, "TUIC queued pre-auth uni-stream command ", buffer[1], " from ", s.quicConn.RemoteAddr())
		// The deferred CancelRead above used to fire the moment this function
		// returned, so the queued task always found a cancelled stream: it failed
		// to read the packet, resumePendingTasks propagated the error and tore
		// down the whole QUIC connection. Any client whose first UDP packet on a
		// uni-stream (udp_relay_mode "quic") overtook its own auth stream lost the
		// entire tunnel.
		cancelRead = false
		s.enqueuePendingTask(func() error {
			defer stream.CancelRead(0)
			return s.handlePendingUniStream(stream, buffer)
		})
		return nil
	default:
		return errors.New("unknown command ", buffer[1])
	}
}

func (s *serverSession) handlePendingUniStream(stream *quic.ReceiveStream, header []byte) error {
	if err := s.waitAuth(); err != nil {
		return err
	}
	switch header[1] {
	case commandPacket:
		message := new(udpMessage)
		if err := readUDPMessage(message, stream); err != nil {
			return err
		}
		errors.LogDebug(s.ctx, "TUIC processed UDP relay packet from uni-stream session=", message.sessionID, " size=", len(message.data), " dest=", message.destination)
		s.handleUDPMessage(message, true)
		return nil
	case commandDissociate:
		var sessionID uint16
		if err := binary.Read(stream, binary.BigEndian, &sessionID); err != nil {
			return err
		}
		s.udpAccess.RLock()
		udpConn := s.udpConnMap[sessionID]
		s.udpAccess.RUnlock()
		if udpConn != nil {
			errors.LogDebug(s.ctx, "TUIC dissociating UDP session ", sessionID, " from ", s.quicConn.RemoteAddr())
			udpConn.closeWithError(io.ErrClosedPipe)
			s.udpAccess.Lock()
			delete(s.udpConnMap, sessionID)
			s.udpAccess.Unlock()
		}
		return nil
	default:
		return errors.New("unknown command ", header[1])
	}
}

// loopHeartbeats sends the server half of the TUIC keepalive. The config knob
// existed but nothing ever sent one: the server only parsed inbound heartbeats,
// so a NAT/CGNAT mapping on a mostly idle association expired from the server
// side with no traffic to refresh it. sing-box's server does the same thing
// (service.go loopHeartbeats), so every client in the wild already accepts it.
// Started after authentication so nothing is written to an unauthenticated peer.
func (s *serverSession) loopHeartbeats() {
	if s.heartbeat <= 0 {
		return
	}
	ticker := time.NewTicker(s.heartbeat)
	defer ticker.Stop()
	for {
		select {
		case <-s.connDone:
			return
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			if err := s.quicConn.SendDatagram([]byte{tuicVersion, commandHeartbeat}); err != nil {
				s.closeWithError(errors.New("send heartbeat").Base(err))
				return
			}
			errors.LogDebug(s.ctx, "TUIC sent heartbeat to ", s.quicConn.RemoteAddr())
		}
	}
}

func (s *serverSession) handleAuthTimeout() {
	timer := time.NewTimer(s.authTimeout)
	defer timer.Stop()
	select {
	case <-s.connDone:
	case <-s.authDone:
	case <-timer.C:
		s.closeWithError(errors.New("authentication timeout"))
	}
}

func (s *serverSession) loopStreams() {
	for {
		stream, err := s.quicConn.AcceptStream(s.ctx)
		if err != nil {
			return
		}
		go func() {
			if err := s.handleStream(stream); err != nil {
				stream.CancelRead(0)
				_ = stream.Close()
				errors.LogWarning(s.ctx, "TUIC stream error: ", err)
			}
		}()
	}
}

func (s *serverSession) handleStream(stream *quic.Stream) error {
	if s.authReady() {
		return s.handlePendingStream(stream)
	}
	errors.LogDebug(s.ctx, "TUIC queued pre-auth connect stream from ", s.quicConn.RemoteAddr())
	s.enqueuePendingTask(func() error {
		return s.handlePendingStream(stream)
	})
	return nil
}

func (s *serverSession) handlePendingStream(stream *quic.Stream) error {
	if err := s.waitAuth(); err != nil {
		return err
	}
	conn := &streamConn{
		Stream: stream,
		local:  s.localAddr,
		remote: s.quicConn.RemoteAddr(),
		user:   s.authUser,
	}
	errors.LogDebug(s.ctx, "TUIC accepting TCP relay stream from ", s.quicConn.RemoteAddr(), " user=", s.authUser.Email)
	s.handler(conn)
	return nil
}

func (s *serverSession) loopMessages() {
	for {
		data, err := s.quicConn.ReceiveDatagram(s.ctx)
		if err != nil {
			s.closeWithError(err)
			return
		}
		if err := s.handleMessage(data); err != nil {
			s.closeWithError(err)
			return
		}
	}
}

func (s *serverSession) handleMessage(data []byte) error {
	if len(data) < 2 {
		return errors.New("invalid message")
	}
	if data[0] != tuicVersion {
		return errors.New("unknown version ", data[0])
	}
	switch data[1] {
	case commandPacket:
		if !s.authReady() {
			errors.LogDebug(s.ctx, "TUIC queued pre-auth datagram from ", s.quicConn.RemoteAddr())
			s.enqueuePendingTask(func() error {
				return s.handleMessage(data)
			})
			return nil
		}
		message := new(udpMessage)
		if err := decodeUDPMessage(message, data[2:]); err != nil {
			return err
		}
		errors.LogDebug(s.ctx, "TUIC processed UDP relay packet from datagram session=", message.sessionID, " size=", len(message.data), " dest=", message.destination)
		s.handleUDPMessage(message, false)
		return nil
	case commandHeartbeat:
		return nil
	default:
		return errors.New("unknown command ", data[1])
	}
}

func (s *serverSession) handleUDPMessage(message *udpMessage, udpStream bool) {
	s.udpAccess.RLock()
	udpConn := s.udpConnMap[message.sessionID]
	s.udpAccess.RUnlock()
	if udpConn == nil || udpConn.done() {
		errors.LogDebug(s.ctx, "TUIC creating UDP relay session ", message.sessionID, " from ", s.quicConn.RemoteAddr(), " viaStream=", udpStream)
		newUDPConn := newUDPPacketConn(s.ctx, s.quicConn, udpStream, true, s.authUser, func() {
			s.udpAccess.Lock()
			delete(s.udpConnMap, message.sessionID)
			s.udpAccess.Unlock()
		})
		newUDPConn.sessionID = message.sessionID
		s.udpAccess.Lock()
		udpConn = s.udpConnMap[message.sessionID]
		if udpConn == nil || udpConn.done() {
			udpConn = newUDPConn
			s.udpConnMap[message.sessionID] = udpConn
			go newUDPConn.watchIdle(s.udpTimeout)
		} else {
			newUDPConn.closeWithError(io.ErrClosedPipe)
		}
		s.udpAccess.Unlock()
	}
	destination := message.destination
	shouldStart := udpConn.markStarted(destination)
	udpConn.inputPacket(message)
	if !shouldStart {
		errors.LogDebug(s.ctx, "TUIC relaying UDP packet for existing session ", message.sessionID)
		return
	}
	errors.LogDebug(s.ctx, "TUIC started UDP relay session ", message.sessionID, " for ", message.destination)
	go func() {
		s.handler(udpConn)
	}()
}

func (s *serverSession) authReady() bool {
	select {
	case <-s.authDone:
		return true
	default:
		return false
	}
}

func (s *serverSession) enqueuePendingTask(task func() error) {
	if task == nil {
		return
	}
	s.pendingAccess.Lock()
	defer s.pendingAccess.Unlock()
	s.pendingTasks = append(s.pendingTasks, task)
}

func (s *serverSession) resumePendingTasks() {
	s.pendingAccess.Lock()
	tasks := s.pendingTasks
	s.pendingTasks = nil
	s.pendingAccess.Unlock()
	for _, task := range tasks {
		if task == nil {
			continue
		}
		if err := task(); err != nil {
			s.closeWithError(errors.New("resume pending task").Base(err))
			return
		}
	}
}

func (s *serverSession) waitAuth() error {
	select {
	case <-s.connDone:
		return s.connErr
	case <-s.authDone:
		return nil
	}
}

func (s *serverSession) closeWithError(err error) {
	s.connAccess.Lock()
	defer s.connAccess.Unlock()
	select {
	case <-s.connDone:
		return
	default:
		s.connErr = err
		close(s.connDone)
	}
	if err != nil && !stderrors.Is(err, context.Canceled) && !stderrors.Is(err, quic.ErrServerClosed) {
		errors.LogWarning(s.ctx, "TUIC connection closed: ", err)
	} else {
		errors.LogDebug(s.ctx, "TUIC connection closed: ", err)
	}
	_ = s.quicConn.CloseWithError(0, "")
}

type streamConn struct {
	*quic.Stream
	local  stdnet.Addr
	remote stdnet.Addr
	user   *protocol.MemoryUser
}

func (c *streamConn) User() *protocol.MemoryUser {
	return c.user
}

func (c *streamConn) LocalAddr() stdnet.Addr {
	return c.local
}

func (c *streamConn) RemoteAddr() stdnet.Addr {
	return c.remote
}

func (c *streamConn) Close() error {
	c.Stream.CancelRead(0)
	return c.Stream.Close()
}
