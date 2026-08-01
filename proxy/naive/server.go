package naive

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	http_proto "github.com/xtls/xray-core/common/protocol/http"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
)

var (
	_ proxy.Inbound     = (*Server)(nil)
	_ proxy.UserManager = (*Server)(nil)
)

// httpStreamConn is what transport/internet/naive hands over for an HTTP/3
// request. It is matched structurally so that the proxy does not have to import
// the transport.
type httpStreamConn interface {
	HTTPRequest() *http.Request
	HTTPResponseWriter() http.ResponseWriter
}

// Server is the naive inbound. One Server serves h1, h2 and h3 through a single
// http.Handler, because CONNECT looks the same on all three once the request
// headers are parsed.
type Server struct {
	config        *ServerConfig
	validator     *Validator
	policyManager policy.Manager
	masquerade    http.Handler
	realm         string
}

// NewServer creates a new naive inbound handler.
func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
	validator := NewValidator()
	for _, user := range config.Clients {
		// Drop the bad account, keep the inbound. Returning an error here makes
		// Xray refuse the ENTIRE config, so one duplicate Basic username would
		// take down every unrelated inbound on the box. That has bitten this
		// fork twice. infra/conf/naive.go screens the same cases earlier; this
		// is the backstop for accounts that arrive by other routes.
		u, err := user.ToMemoryUser()
		if err != nil {
			errors.LogWarningInner(ctx, err, "naive: dropping client ", user.Email)
			continue
		}
		if err := validator.Add(u); err != nil {
			errors.LogWarningInner(ctx, err, "naive: dropping client ", user.Email)
			continue
		}
	}

	// Not an error: an inbound may legitimately start empty and get its accounts
	// hot-added over gRPC. It is worth a warning because the symptom is so
	// misleading: the port listens, the masquerade serves a working website,
	// and every CONNECT answers 407, which reads as a broken protocol rather
	// than as an inbound with nothing to authenticate against.
	if validator.GetCount() == 0 {
		errors.LogWarning(ctx, "naive: inbound has no clients, so every CONNECT will be refused with 407 and only the masquerade will answer")
	}

	masquerade, err := buildMasquerade(config.Masquerade)
	if err != nil {
		return nil, err
	}

	realm := config.Realm
	if realm == "" {
		realm = "Proxy"
	}

	v := core.MustFromContext(ctx)
	return &Server{
		config:        config,
		validator:     validator,
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		masquerade:    masquerade,
		realm:         realm,
	}, nil
}

// Network implements proxy.Inbound. Both wires are driven by the stream worker:
// plain TLS/TCP for h1+h2, and transport/internet/naive, which turns every
// HTTP/3 request into a conn, for h3.
func (*Server) Network() []net.Network {
	return []net.Network{net.Network_TCP, net.Network_UNIX}
}

// AddUser implements proxy.UserManager.
func (s *Server) AddUser(ctx context.Context, u *protocol.MemoryUser) error {
	return s.validator.Add(u)
}

// RemoveUser implements proxy.UserManager.
func (s *Server) RemoveUser(ctx context.Context, email string) error {
	return s.validator.Del(email)
}

// GetUser implements proxy.UserManager.
func (s *Server) GetUser(ctx context.Context, email string) *protocol.MemoryUser {
	return s.validator.GetByEmail(email)
}

// GetUsers implements proxy.UserManager.
func (s *Server) GetUsers(ctx context.Context) []*protocol.MemoryUser {
	return s.validator.GetAll()
}

// GetUsersCount implements proxy.UserManager.
func (s *Server) GetUsersCount(context.Context) int64 {
	return s.validator.GetCount()
}

// Process implements proxy.Inbound.
func (s *Server) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	inbound := session.InboundFromContext(ctx)
	if inbound != nil {
		inbound.Name = "naive"
		inbound.CanSpliceCopy = 3
		if inbound.User == nil {
			inbound.User = &protocol.MemoryUser{}
		}
	}

	if hc, ok := stat.TryUnwrapStatsConn(conn).(httpStreamConn); ok {
		s.serve(ctx, hc.HTTPResponseWriter(), hc.HTTPRequest(), dispatcher)
		return nil
	}

	return s.serveStream(ctx, conn, dispatcher)
}

// oneShotListener feeds a single already-accepted conn to net/http, which is
// what lets an ordinary proxy.Inbound host a real HTTP server. Using net/http
// (rather than hand-rolling responses) is deliberate: the masquerade must be
// byte-for-byte a normal web server to an active prober.
type oneShotListener struct {
	conn net.Conn
	ch   chan net.Conn
}

func newOneShotListener(conn net.Conn) *oneShotListener {
	l := &oneShotListener{conn: conn, ch: make(chan net.Conn, 1)}
	l.ch <- conn
	close(l.ch)
	return l
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	if c, ok := <-l.ch; ok {
		return c, nil
	}
	return nil, io.EOF
}

func (l *oneShotListener) Close() error   { return nil }
func (l *oneShotListener) Addr() net.Addr { return l.conn.LocalAddr() }

// trackedConn reports when net/http (or our own CONNECT handler) is finished
// with the connection, so Process can block for exactly that long.
type trackedConn struct {
	stat.Connection
	done chan struct{}
	once sync.Once
}

func (c *trackedConn) Close() error {
	c.once.Do(func() { close(c.done) })
	return c.Connection.Close()
}

func (s *Server) serveStream(ctx context.Context, conn stat.Connection, dispatcher routing.Dispatcher) error {
	tracked := &trackedConn{Connection: conn, done: make(chan struct{})}

	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	// The TLS layer is already terminated by the transport, so from net/http's
	// point of view an ALPN-negotiated h2 client is a prior-knowledge h2c one.
	protocols.SetUnencryptedHTTP2(true)

	server := &http.Server{
		Handler:           s.handler(ctx, dispatcher),
		ReadHeaderTimeout: s.policy().Timeouts.Handshake,
		IdleTimeout:       s.policy().Timeouts.ConnectionIdle,
		Protocols:         protocols,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}

	go func() {
		_ = server.Serve(newOneShotListener(tracked))
	}()

	select {
	case <-tracked.done:
	case <-ctx.Done():
	}
	_ = server.Close()
	return nil
}

func (s *Server) policy() policy.Session {
	return s.policyManager.ForLevel(0)
}

func (s *Server) handler(connCtx context.Context, dispatcher routing.Dispatcher) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.serve(connCtx, w, r, dispatcher)
	})
}

func parseBasicAuth(auth string) (username, password string, ok bool) {
	const prefix = "Basic "
	if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return
	}
	c, err := base64.StdEncoding.DecodeString(strings.TrimSpace(auth[len(prefix):]))
	if err != nil {
		return
	}
	cs := string(c)
	i := strings.IndexByte(cs, ':')
	if i < 0 {
		return
	}
	return cs[:i], cs[i+1:], true
}

// connectAuthority resolves the CONNECT target. `-connect-authority` comes
// first because Cronet puts it there and some clients send nothing else.
func connectAuthority(r *http.Request) string {
	if v := r.Header.Get(headerConnectAuthority); v != "" {
		return v
	}
	if r.Host != "" {
		return r.Host
	}
	if r.URL != nil && r.URL.Host != "" {
		return r.URL.Host
	}
	return ""
}

// serve is the single entry point for h1, h2 and h3.
func (s *Server) serve(connCtx context.Context, w http.ResponseWriter, r *http.Request, dispatcher routing.Dispatcher) {
	if !strings.EqualFold(r.Method, http.MethodConnect) {
		// Everything that is not a proxy request, including naiveproxy's own
		// preamble GETs, is answered by the masquerade site.
		s.masquerade.ServeHTTP(w, r)
		return
	}

	user := s.authenticate(r)
	if user == nil {
		// The challenge is mandatory, not cosmetic: Cronet does not send
		// credentials pre-emptively and only retries after a 407 that carries
		// Proxy-Authenticate.
		w.Header().Set(headerProxyAuthenticate, `Basic realm="`+s.realm+`", charset="UTF-8"`)
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusProxyAuthRequired)
		return
	}

	authority := connectAuthority(r)
	if authority == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	dest, err := http_proto.ParseHost(authority, net.Port(443))
	if err != nil {
		errors.LogInfoInner(connCtx, err, "naive: malformed CONNECT authority ", authority)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	paddingType := NegotiateServerPadding(r.Header)

	ctx := s.subContext(connCtx, user)
	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   r.RemoteAddr,
		To:     dest,
		Status: log.AccessAccepted,
		Reason: "",
		Email:  user.Email,
	})
	errors.LogInfo(ctx, "naive: tunnelling request to ", dest)

	reader, writer, closer, err := s.accept(w, r, paddingType)
	if err != nil {
		errors.LogInfoInner(ctx, err, "naive: failed to accept CONNECT")
		return
	}
	if closer != nil {
		defer closer()
	}

	if paddingType == PaddingTypeVariant1 {
		reader = newPaddingReader(reader)
		writer = newPaddingWriter(writer)
	}

	if err := dispatcher.DispatchLink(ctx, dest, &transport.Link{
		Reader: buf.NewReader(reader),
		Writer: buf.NewWriter(writer),
	}); err != nil {
		errors.LogInfoInner(ctx, err, "naive: failed to dispatch request")
	}
}

// accept answers 200 and returns the tunnel's two halves. HTTP/1.1 is hijacked
// (naiveproxy itself considers h1 dead, but a hijack is free and keeps active
// probers honest); h2 and h3 stream through the request body and the response
// writer, with an explicit flush on every write.
func (s *Server) accept(w http.ResponseWriter, r *http.Request, paddingType int) (io.Reader, io.Writer, func(), error) {
	if r.ProtoMajor == 1 {
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			return nil, nil, nil, errors.New("naive: HTTP/1.1 response is not hijackable")
		}
		conn, brw, err := hijacker.Hijack()
		if err != nil {
			return nil, nil, nil, errors.New("naive: hijack failed").Base(err)
		}
		var response strings.Builder
		response.WriteString("HTTP/1.1 200 Connection established\r\n")
		if paddingType == PaddingTypeVariant1 {
			response.WriteString(headerPadding + ": " + ReplyPaddingHeader() + "\r\n")
			response.WriteString(headerPaddingTypeReply + ": 1\r\n")
		}
		response.WriteString("\r\n")
		if _, err := brw.WriteString(response.String()); err != nil {
			conn.Close()
			return nil, nil, nil, err
		}
		if err := brw.Flush(); err != nil {
			conn.Close()
			return nil, nil, nil, err
		}
		var reader io.Reader = conn
		if brw.Reader.Buffered() > 0 {
			reader = io.MultiReader(io.LimitReader(brw.Reader, int64(brw.Reader.Buffered())), conn)
		}
		return reader, conn, func() { conn.Close() }, nil
	}

	if paddingType == PaddingTypeVariant1 {
		w.Header().Set(headerPadding, ReplyPaddingHeader())
		w.Header().Set(headerPaddingTypeReply, "1")
	}
	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	var reader io.Reader = r.Body
	if reader == nil {
		reader = strings.NewReader("")
	}
	return reader, newFlushWriter(w), nil, nil
}

func (s *Server) authenticate(r *http.Request) *protocol.MemoryUser {
	if s.validator.GetCount() == 0 {
		return nil
	}
	username, password, ok := parseBasicAuth(r.Header.Get(headerProxyAuthorization))
	if !ok {
		return nil
	}
	return s.validator.Get(username, password)
}

// subContext gives each CONNECT stream its own session, because a single h2 or
// h3 connection carries many of them. Setting Inbound.User is what wires the
// stream into per-account statistics, the speed limiter, the IP/device limiter
// and online detection; CanSpliceCopy = 3 keeps the limiter in the data path.
//
// Every one of those keys off user.Email, never off the Basic username the
// client actually sent. The split is deliberate: the username is only a
// credential and an account may change it, while the email is the identity the
// panel's client_traffics rows, quota and expiry are written against. Handing
// the username down here would silently unhook all of them, with traffic still
// flowing and nothing logging an error.
func (s *Server) subContext(ctx context.Context, user *protocol.MemoryUser) context.Context {
	newContent := session.Content{}
	if content := session.ContentFromContext(ctx); content != nil {
		newContent = *content
		newContent.Attributes = nil
	}
	ctx = session.ContextWithContent(ctx, &newContent)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{}})

	if inbound := session.InboundFromContext(ctx); inbound != nil {
		newInbound := *inbound
		newInbound.Name = "naive"
		newInbound.CanSpliceCopy = 3
		newInbound.User = user
		ctx = session.ContextWithInbound(ctx, &newInbound)
	}
	return ctx
}

func init() {
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewServer(ctx, config.(*ServerConfig))
	}))
}
