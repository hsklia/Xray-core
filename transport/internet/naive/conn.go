package naive

import (
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// requestConn adapts a single in-flight HTTP/3 request to net.Conn so that it
// can be pushed through internet.ConnHandler and end up in the naive inbound's
// Process(), which is where every naive-protocol decision lives.
//
// The inbound recognises it structurally (HTTPRequest/HTTPResponseWriter) and
// drives the exchange from the http.ResponseWriter, so Read/Write here are only
// a fallback for generic plumbing.
type requestConn struct {
	w      http.ResponseWriter
	r      *http.Request
	flush  http.Flusher
	local  net.Addr
	remote net.Addr

	done      chan struct{}
	closeOnce sync.Once

	writeMu sync.Mutex
}

func newRequestConn(w http.ResponseWriter, r *http.Request, local net.Addr) *requestConn {
	c := &requestConn{
		w:      w,
		r:      r,
		local:  local,
		remote: parseAddr(r.RemoteAddr),
		done:   make(chan struct{}),
	}
	c.flush, _ = w.(http.Flusher)
	return c
}

// parseAddr turns quic-go's "ip:port" RemoteAddr string into a *net.TCPAddr.
// TCP (not UDP) is deliberate: the inbound is driven by the stream worker, so
// session.Inbound.Source must read as a TCP destination for the routing,
// statistics and IP-limiter code paths.
func parseAddr(s string) net.Addr {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return &net.TCPAddr{}
	}
	p, _ := strconv.Atoi(port)
	return &net.TCPAddr{IP: net.ParseIP(host), Port: p}
}

// HTTPRequest exposes the request that opened this stream.
func (c *requestConn) HTTPRequest() *http.Request { return c.r }

// HTTPResponseWriter exposes the writer for this stream.
func (c *requestConn) HTTPResponseWriter() http.ResponseWriter { return c.w }

func (c *requestConn) Read(b []byte) (int, error) {
	if c.r.Body == nil {
		return 0, io.EOF
	}
	return c.r.Body.Read(b)
}

func (c *requestConn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	select {
	case <-c.done:
		return 0, io.ErrClosedPipe
	default:
	}
	n, err := c.w.Write(b)
	if err == nil && c.flush != nil {
		c.flush.Flush()
	}
	return n, err
}

// Close releases the handler goroutine that is parked on Wait, which is what
// finally completes the HTTP/3 response.
func (c *requestConn) Close() error {
	c.closeOnce.Do(func() { close(c.done) })
	return nil
}

// Wait blocks until Close is called.
func (c *requestConn) Wait() <-chan struct{} { return c.done }

func (c *requestConn) LocalAddr() net.Addr  { return c.local }
func (c *requestConn) RemoteAddr() net.Addr { return c.remote }

func (c *requestConn) SetDeadline(time.Time) error      { return nil }
func (c *requestConn) SetReadDeadline(time.Time) error  { return nil }
func (c *requestConn) SetWriteDeadline(time.Time) error { return nil }

// streamConn is the client-side counterpart: an HTTP/3 request stream that has
// already exchanged CONNECT headers, presented as a net.Conn.
type streamConn struct {
	stream interface {
		io.Reader
		io.Writer
		io.Closer
		SetDeadline(time.Time) error
		SetReadDeadline(time.Time) error
		SetWriteDeadline(time.Time) error
	}
	local  net.Addr
	remote net.Addr
}

func (c *streamConn) Read(b []byte) (int, error)  { return c.stream.Read(b) }
func (c *streamConn) Write(b []byte) (int, error) { return c.stream.Write(b) }
func (c *streamConn) Close() error                { return c.stream.Close() }

// CloseWrite half-closes the stream. QUIC's Close only ends the send side, so
// this is exactly what the naive outbound needs when its uplink runs dry.
func (c *streamConn) CloseWrite() error { return c.stream.Close() }

func (c *streamConn) LocalAddr() net.Addr                { return c.local }
func (c *streamConn) RemoteAddr() net.Addr               { return c.remote }
func (c *streamConn) SetDeadline(t time.Time) error      { return c.stream.SetDeadline(t) }
func (c *streamConn) SetReadDeadline(t time.Time) error  { return c.stream.SetReadDeadline(t) }
func (c *streamConn) SetWriteDeadline(t time.Time) error { return c.stream.SetWriteDeadline(t) }
