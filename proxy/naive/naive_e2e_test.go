package naive_test

import (
	"bufio"
	"bytes"
	"context"
	gotls "crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"golang.org/x/net/http2"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/main/distro/all"
	"github.com/xtls/xray-core/proxy/naive"
	tcpserver "github.com/xtls/xray-core/testing/servers/tcp"
)

const (
	testEmail    = "alice@example.com"
	testPassword = "hunter2"
	masqBody     = "<html><body><h1>Nothing to see here</h1></body></html>"
)

func startXray(t *testing.T, config string) {
	t.Helper()
	cfg, err := core.LoadConfig("json", strings.NewReader(config))
	if err != nil {
		t.Fatalf("load config: %v\n%s", err, config)
	}
	instance, err := core.New(cfg)
	if err != nil {
		t.Fatalf("new instance: %v", err)
	}
	if err := instance.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { instance.Close() })
}

// targetServer is what the tunnel is pointed at.
func targetServer(t *testing.T) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "tunnelled ok")
	}))
	t.Cleanup(s.Close)
	return s
}

func selfSignedPEM(t *testing.T) (certPEM, keyPEM, pinHex string) {
	t.Helper()
	ca, _ := cert.MustGenerate(nil, cert.Authority(true), cert.KeyUsage(0x04|0x20)) // CertSign | CRLSign
	leaf, hash := cert.MustGenerate(ca, cert.CommonName("localhost"), cert.DNSNames("localhost"))
	c, k := leaf.ToPEM()
	return string(c), string(k), hex.EncodeToString(hash[:])
}

func jsonList(lines []string) string {
	b, _ := json.Marshal(lines)
	return string(b)
}

func naiveSettingsJSON() string {
	return `{
		"clients": [{"email": "` + testEmail + `", "password": "` + testPassword + `"}],
		"network": "tcp,udp",
		"masquerade": {
			"type": "string",
			"string": ` + mustJSON(masqBody) + `,
			"statusCode": 200,
			"headers": {"Content-Type": "text/html; charset=utf-8"}
		}
	}`
}

func mustJSON(v interface{}) string {
	b, err := json.Marshal(v)
	common.Must(err)
	return string(b)
}

// connectHeader builds exactly what naiveproxy's client sends.
func connectHeader(authority string, withAuth bool) http.Header {
	h := http.Header{}
	if withAuth {
		h.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(testEmail+":"+testPassword)))
	}
	h.Set("padding", naive.RequestPaddingHeader())
	h.Set("padding-type-request", "1, 0")
	h.Set("-connect-authority", authority)
	return h
}

// padWrite frames one payload the way a Variant1 client does.
func padWrite(w io.Writer, payload []byte, padSize int) error {
	head := make([]byte, 3)
	binary.BigEndian.PutUint16(head[0:2], uint16(len(payload)))
	head[2] = byte(padSize)
	frame := append(head, payload...)
	frame = append(frame, make([]byte, padSize)...)
	_, err := w.Write(frame)
	return err
}

// readPaddedFrame reads and validates one Variant1 frame.
func readPaddedFrame(t *testing.T, r io.Reader) []byte {
	t.Helper()
	head := make([]byte, 3)
	if _, err := io.ReadFull(r, head); err != nil {
		t.Fatalf("read frame header: %v", err)
	}
	size := int(binary.BigEndian.Uint16(head[0:2]))
	pad := int(head[2])
	payload := make([]byte, size)
	if _, err := io.ReadFull(r, payload); err != nil {
		t.Fatalf("read frame payload: %v", err)
	}
	padding := make([]byte, pad)
	if _, err := io.ReadFull(r, padding); err != nil {
		t.Fatalf("read frame padding: %v", err)
	}
	for _, b := range padding {
		if b != 0 {
			t.Fatal("padding must be zero-filled")
		}
	}
	return payload
}

// roundTripCONNECT drives one CONNECT over an established h2 client conn.
func roundTripCONNECT(t *testing.T, cc *http2.ClientConn, authority string, withAuth bool) (*http.Response, *io.PipeWriter) {
	t.Helper()
	body, writer := io.Pipe()
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    mustURL("https://" + authority),
		Host:   authority,
		Header: connectHeader(authority, withAuth),
		Body:   body,
	}
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("CONNECT round trip: %v", err)
	}
	return resp, writer
}

func mustURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	common.Must(err)
	return u
}

func TestNaiveH2Plaintext(t *testing.T) {
	target := targetServer(t)
	port := tcpserver.PickPort()

	startXray(t, `{
		"log": {"loglevel": "error"},
		"inbounds": [{
			"listen": "127.0.0.1",
			"port": `+fmt.Sprint(port)+`,
			"protocol": "naive",
			"settings": `+naiveSettingsJSON()+`
		}],
		"outbounds": [{"protocol": "freedom"}]
	}`)
	time.Sleep(300 * time.Millisecond)

	runH2Suite(t, fmt.Sprintf("127.0.0.1:%d", port), nil, target.Listener.Addr().String())
}

func TestNaiveH2OverNaiveTransportTLS(t *testing.T) {
	target := targetServer(t)
	port := tcpserver.PickPort()
	certPEM, keyPEM, _ := selfSignedPEM(t)

	startXray(t, `{
		"log": {"loglevel": "error"},
		"inbounds": [{
			"listen": "127.0.0.1",
			"port": `+fmt.Sprint(port)+`,
			"protocol": "naive",
			"settings": `+naiveSettingsJSON()+`,
			"streamSettings": {
				"network": "naive",
				"security": "tls",
				"naiveSettings": {"network": "tcp,udp"},
				"tlsSettings": {
					"serverName": "localhost",
					"certificates": [{
						"certificate": `+jsonList(strings.Split(strings.TrimRight(certPEM, "\n"), "\n"))+`,
						"key": `+jsonList(strings.Split(strings.TrimRight(keyPEM, "\n"), "\n"))+`
					}]
				}
			}
		}],
		"outbounds": [{"protocol": "freedom"}]
	}`)
	time.Sleep(300 * time.Millisecond)

	runH2Suite(t, fmt.Sprintf("127.0.0.1:%d", port), &gotls.Config{
		InsecureSkipVerify: true,
		ServerName:         "localhost",
		NextProtos:         []string{"h2"},
	}, target.Listener.Addr().String())

	runH3Suite(t, fmt.Sprintf("127.0.0.1:%d", port), target.Listener.Addr().String())
}

func dialH2(t *testing.T, addr string, tlsConfig *gotls.Config) *http2.ClientConn {
	t.Helper()
	var conn net.Conn
	var err error
	if tlsConfig != nil {
		conn, err = gotls.Dial("tcp", addr, tlsConfig)
	} else {
		conn, err = net.Dial("tcp", addr)
	}
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	cc, err := (&http2.Transport{}).NewClientConn(conn)
	if err != nil {
		t.Fatalf("h2 handshake: %v", err)
	}
	return cc
}

func runH2Suite(t *testing.T, addr string, tlsConfig *gotls.Config, targetAddr string) {
	t.Run("masquerade serves a real page", func(t *testing.T) {
		cc := dialH2(t, addr, tlsConfig)
		req, _ := http.NewRequest(http.MethodGet, "https://"+addr+"/", nil)
		resp, err := cc.RoundTrip(req)
		if err != nil {
			t.Fatalf("GET /: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("GET / returned %d, want 200 from the masquerade", resp.StatusCode)
		}
		b, _ := io.ReadAll(resp.Body)
		if string(b) != masqBody {
			t.Fatalf("GET / body = %q, want the masquerade page", b)
		}
	})

	t.Run("unauthenticated CONNECT gets a 407 challenge", func(t *testing.T) {
		cc := dialH2(t, addr, tlsConfig)
		resp, writer := roundTripCONNECT(t, cc, targetAddr, false)
		defer resp.Body.Close()
		defer writer.Close()
		if resp.StatusCode != http.StatusProxyAuthRequired {
			t.Fatalf("status %d, want 407", resp.StatusCode)
		}
		challenge := resp.Header.Get("Proxy-Authenticate")
		if !strings.HasPrefix(challenge, "Basic realm=") {
			t.Fatalf("Proxy-Authenticate = %q, want a Basic realm challenge", challenge)
		}
	})

	t.Run("authenticated CONNECT tunnels with Variant1 padding", func(t *testing.T) {
		cc := dialH2(t, addr, tlsConfig)
		resp, writer := roundTripCONNECT(t, cc, targetAddr, true)
		defer resp.Body.Close()
		defer writer.Close()

		if resp.StatusCode != 200 {
			t.Fatalf("status %d, want 200", resp.StatusCode)
		}
		if got := resp.Header.Get("padding-type-reply"); got != "1" {
			t.Fatalf("padding-type-reply = %q, want \"1\"", got)
		}
		if p := resp.Header.Get("padding"); len(p) < 30 || len(p) > 62 {
			t.Fatalf("reply padding header is %d bytes, want 30..62", len(p))
		}

		exercisePaddedTunnel(t, resp.Body, writer, targetAddr)
	})
}

// exercisePaddedTunnel speaks HTTP through the tunnel with Variant1 framing and
// asserts the server frames its first eight writes and then goes raw.
func exercisePaddedTunnel(t *testing.T, down io.Reader, up io.Writer, targetAddr string) {
	t.Helper()
	request := []byte("GET / HTTP/1.1\r\nHost: " + targetAddr + "\r\nConnection: close\r\n\r\n")
	if err := padWrite(up, request, 37); err != nil {
		t.Fatalf("padded write: %v", err)
	}

	// The first frame back must be padded, and must contain the status line.
	first := readPaddedFrame(t, down)
	if !bytes.Contains(first, []byte("HTTP/1.1 200")) {
		t.Fatalf("first framed response chunk = %q, want an HTTP status line", first)
	}

	// Drain the rest; whatever the framing, the payload must contain the body.
	got := append([]byte{}, first...)
	deadline := time.Now().Add(5 * time.Second)
	for !bytes.Contains(got, []byte("tunnelled ok")) && time.Now().Before(deadline) {
		buf := make([]byte, 4096)
		n, err := down.Read(buf)
		got = append(got, buf[:n]...)
		if err != nil {
			break
		}
	}
	if !bytes.Contains(got, []byte("tunnelled ok")) {
		t.Fatalf("tunnel did not carry the target's body, got %q", got)
	}
}

func runH3Suite(t *testing.T, addr string, targetAddr string) {
	tlsConfig := &gotls.Config{
		InsecureSkipVerify: true,
		ServerName:         "localhost",
		NextProtos:         []string{http3.NextProtoH3},
	}

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	common.Must(err)
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	common.Must(err)
	t.Cleanup(func() { pc.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	quicConn, err := quic.DialEarly(ctx, pc, udpAddr, tlsConfig, &quic.Config{MaxIdleTimeout: 30 * time.Second})
	if err != nil {
		t.Fatalf("QUIC dial: %v", err)
	}
	t.Cleanup(func() { quicConn.CloseWithError(0, "") })

	cc := (&http3.Transport{}).NewClientConn(quicConn)

	t.Run("h3 masquerade serves a real page", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "https://localhost/", nil)
		resp, err := cc.RoundTrip(req)
		if err != nil {
			t.Fatalf("h3 GET /: %v", err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 || string(b) != masqBody {
			t.Fatalf("h3 GET / = %d %q, want the masquerade page", resp.StatusCode, b)
		}
	})

	t.Run("h3 CONNECT tunnels with Variant1 padding", func(t *testing.T) {
		stream, err := cc.OpenRequestStream(context.Background())
		if err != nil {
			t.Fatalf("open request stream: %v", err)
		}
		req := &http.Request{
			Method: http.MethodConnect,
			URL:    mustURL("https://" + targetAddr),
			Host:   targetAddr,
			Header: connectHeader(targetAddr, true),
		}
		if err := stream.SendRequestHeader(req); err != nil {
			t.Fatalf("send CONNECT: %v", err)
		}
		resp, err := stream.ReadResponse()
		if err != nil {
			t.Fatalf("read CONNECT response: %v", err)
		}
		if resp.StatusCode != 200 {
			t.Fatalf("h3 CONNECT status %d, want 200", resp.StatusCode)
		}
		if got := resp.Header.Get("padding-type-reply"); got != "1" {
			t.Fatalf("h3 padding-type-reply = %q, want \"1\"", got)
		}
		exercisePaddedTunnel(t, stream, stream, targetAddr)
	})

	t.Run("h3 unauthenticated CONNECT gets a 407 challenge", func(t *testing.T) {
		stream, err := cc.OpenRequestStream(context.Background())
		if err != nil {
			t.Fatalf("open request stream: %v", err)
		}
		req := &http.Request{
			Method: http.MethodConnect,
			URL:    mustURL("https://" + targetAddr),
			Host:   targetAddr,
			Header: connectHeader(targetAddr, false),
		}
		common.Must(stream.SendRequestHeader(req))
		resp, err := stream.ReadResponse()
		if err != nil {
			t.Fatalf("read response: %v", err)
		}
		if resp.StatusCode != http.StatusProxyAuthRequired {
			t.Fatalf("h3 status %d, want 407", resp.StatusCode)
		}
		if !strings.HasPrefix(resp.Header.Get("Proxy-Authenticate"), "Basic realm=") {
			t.Fatal("h3 407 is missing its Proxy-Authenticate challenge")
		}
	})
}

// TestNaiveOutboundThroughNaiveInbound closes the loop: an HTTP inbound routed
// into the naive outbound, which dials a naive inbound in the same process.
func TestNaiveOutboundThroughNaiveInbound(t *testing.T) {
	target := targetServer(t)
	serverPort := tcpserver.PickPort()
	clientPort := tcpserver.PickPort()

	startXray(t, `{
		"log": {"loglevel": "error"},
		"inbounds": [{
			"listen": "127.0.0.1",
			"port": `+fmt.Sprint(serverPort)+`,
			"protocol": "naive",
			"settings": `+naiveSettingsJSON()+`
		}],
		"outbounds": [{"protocol": "freedom"}]
	}`)

	startXray(t, `{
		"log": {"loglevel": "error"},
		"inbounds": [{
			"listen": "127.0.0.1",
			"port": `+fmt.Sprint(clientPort)+`,
			"protocol": "http",
			"settings": {}
		}],
		"outbounds": [{
			"protocol": "naive",
			"settings": {
				"address": "127.0.0.1",
				"port": `+fmt.Sprint(serverPort)+`,
				"email": "`+testEmail+`",
				"password": "`+testPassword+`",
				"network": "tcp"
			}
		}]
	}`)
	time.Sleep(500 * time.Millisecond)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustURL(fmt.Sprintf("http://127.0.0.1:%d", clientPort))),
		},
		Timeout: 10 * time.Second,
	}
	resp, err := client.Get(target.URL)
	if err != nil {
		t.Fatalf("request through the naive outbound: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if string(b) != "tunnelled ok" {
		t.Fatalf("body %q, want the target's response", b)
	}
}

// TestNaiveOutboundH3 exercises transport/internet/naive's dialer: an HTTP
// inbound routed into a naive outbound that speaks CONNECT over HTTP/3.
func TestNaiveOutboundH3(t *testing.T) {
	target := targetServer(t)
	serverPort := tcpserver.PickPort()
	clientPort := tcpserver.PickPort()
	certPEM, keyPEM, pinHex := selfSignedPEM(t)

	startXray(t, `{
		"log": {"loglevel": "error"},
		"inbounds": [{
			"listen": "127.0.0.1",
			"port": `+fmt.Sprint(serverPort)+`,
			"protocol": "naive",
			"settings": `+naiveSettingsJSON()+`,
			"streamSettings": {
				"network": "naive",
				"security": "tls",
				"naiveSettings": {"network": "udp"},
				"tlsSettings": {
					"serverName": "localhost",
					"certificates": [{
						"certificate": `+jsonList(strings.Split(strings.TrimRight(certPEM, "\n"), "\n"))+`,
						"key": `+jsonList(strings.Split(strings.TrimRight(keyPEM, "\n"), "\n"))+`
					}]
				}
			}
		}],
		"outbounds": [{"protocol": "freedom"}]
	}`)

	startXray(t, `{
		"log": {"loglevel": "error"},
		"inbounds": [{
			"listen": "127.0.0.1",
			"port": `+fmt.Sprint(clientPort)+`,
			"protocol": "http",
			"settings": {}
		}],
		"outbounds": [{
			"protocol": "naive",
			"settings": {
				"address": "127.0.0.1",
				"port": `+fmt.Sprint(serverPort)+`,
				"email": "`+testEmail+`",
				"password": "`+testPassword+`",
				"network": "udp"
			},
			"streamSettings": {
				"network": "naive",
				"security": "tls",
				"tlsSettings": {"serverName": "localhost", "pinnedPeerCertSha256": "`+pinHex+`"}
			}
		}]
	}`)
	time.Sleep(500 * time.Millisecond)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustURL(fmt.Sprintf("http://127.0.0.1:%d", clientPort))),
		},
		Timeout: 15 * time.Second,
	}
	// Two requests, so the second one exercises the pooled HTTP/3 client conn.
	for i := 0; i < 2; i++ {
		resp, err := client.Get(target.URL)
		if err != nil {
			t.Fatalf("request %d through the naive h3 outbound: %v", i, err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(b) != "tunnelled ok" {
			t.Fatalf("request %d body %q, want the target's response", i, b)
		}
	}
}

// TestNaiveHTTP1Connect covers the hijack path. naiveproxy itself no longer
// uses h1, but an active prober might, and the masquerade must hold there too.
func TestNaiveHTTP1Connect(t *testing.T) {
	target := targetServer(t)
	port := tcpserver.PickPort()
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	startXray(t, `{
		"log": {"loglevel": "error"},
		"inbounds": [{
			"listen": "127.0.0.1",
			"port": `+fmt.Sprint(port)+`,
			"protocol": "naive",
			"settings": `+naiveSettingsJSON()+`
		}],
		"outbounds": [{"protocol": "freedom"}]
	}`)
	time.Sleep(300 * time.Millisecond)

	t.Run("masquerade over h1", func(t *testing.T) {
		resp, err := http.Get("http://" + addr + "/")
		if err != nil {
			t.Fatalf("h1 GET /: %v", err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 || string(b) != masqBody {
			t.Fatalf("h1 GET / = %d %q, want the masquerade page", resp.StatusCode, b)
		}
	})

	t.Run("407 over h1", func(t *testing.T) {
		conn, err := net.Dial("tcp", addr)
		common.Must(err)
		defer conn.Close()
		fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target.Listener.Addr(), target.Listener.Addr())
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatalf("read response: %v", err)
		}
		if resp.StatusCode != http.StatusProxyAuthRequired {
			t.Fatalf("status %d, want 407", resp.StatusCode)
		}
		if !strings.HasPrefix(resp.Header.Get("Proxy-Authenticate"), "Basic realm=") {
			t.Fatal("h1 407 is missing its Proxy-Authenticate challenge")
		}
	})

	t.Run("padded tunnel over h1", func(t *testing.T) {
		conn, err := net.Dial("tcp", addr)
		common.Must(err)
		defer conn.Close()
		targetAddr := target.Listener.Addr().String()
		fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", targetAddr, targetAddr)
		fmt.Fprintf(conn, "Proxy-Authorization: Basic %s\r\n", base64.StdEncoding.EncodeToString([]byte(testEmail+":"+testPassword)))
		fmt.Fprintf(conn, "padding: %s\r\npadding-type-request: 1, 0\r\n\r\n", naive.RequestPaddingHeader())

		reader := bufio.NewReader(conn)
		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatalf("read CONNECT response: %v", err)
		}
		if resp.StatusCode != 200 {
			t.Fatalf("status %d, want 200", resp.StatusCode)
		}
		if got := resp.Header.Get("padding-type-reply"); got != "1" {
			t.Fatalf("h1 padding-type-reply = %q, want \"1\"", got)
		}
		exercisePaddedTunnel(t, reader, conn, targetAddr)
	})
}

// TestConnectAuthorityHeaderWins pins the Cronet quirk: when -connect-authority
// and :authority disagree, the former decides. sing-box's naive outbound relies
// on this, so ignoring it would lock those clients out.
func TestConnectAuthorityHeaderWins(t *testing.T) {
	target := targetServer(t)
	port := tcpserver.PickPort()
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	startXray(t, `{
		"log": {"loglevel": "error"},
		"inbounds": [{
			"listen": "127.0.0.1",
			"port": `+fmt.Sprint(port)+`,
			"protocol": "naive",
			"settings": `+naiveSettingsJSON()+`
		}],
		"outbounds": [{"protocol": "freedom"}]
	}`)
	time.Sleep(300 * time.Millisecond)

	targetAddr := target.Listener.Addr().String()
	cc := dialH2(t, addr, nil)

	body, writer := io.Pipe()
	defer writer.Close()
	header := connectHeader(targetAddr, true)
	// :authority points somewhere unroutable; only the header can save us.
	const decoy = "192.0.2.1:9"
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    mustURL("https://" + decoy),
		Host:   decoy,
		Header: header,
		Body:   body,
	}
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("CONNECT: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	exercisePaddedTunnel(t, resp.Body, writer, targetAddr)
}

// naiveOutboundClientConfig builds the exact JSON the panel emits for a naive
// outbound, so a panel-side shape change that breaks dialing fails here.
func naiveOutboundClientConfig(clientPort, serverPort uint32, network, streamNetwork, alpn, pinHex, fingerprint string) string {
	fp := ""
	if fingerprint != "" {
		fp = `"fingerprint": "` + fingerprint + `",`
	}
	return `{
		"log": {"loglevel": "error"},
		"inbounds": [{
			"listen": "127.0.0.1",
			"port": ` + fmt.Sprint(clientPort) + `,
			"protocol": "http",
			"settings": {}
		}],
		"outbounds": [{
			"protocol": "naive",
			"settings": {
				"address": "127.0.0.1",
				"port": ` + fmt.Sprint(serverPort) + `,
				"email": "` + testEmail + `",
				"password": "` + testPassword + `",
				"network": "` + network + `"
			},
			"streamSettings": {
				"network": "` + streamNetwork + `",
				"security": "tls",
				"tlsSettings": {
					"serverName": "localhost",
					` + fp + `
					"alpn": ["` + alpn + `"],
					"pinnedPeerCertSha256": "` + pinHex + `"
				}
			}
		}]
	}`
}

// TestPanelOutboundShapes pins the outbound config the panel writes, including
// the case where settings.network and streamSettings.network disagree:
// NormalizeNaiveOutboundStream is what makes that harmless rather than a dead
// outbound whose only symptom is a CONNECT that never happens.
func TestPanelOutboundShapes(t *testing.T) {
	cases := []struct {
		name          string
		network       string
		streamNetwork string
		alpn          string
		fingerprint   string
	}{
		{"h2 as the panel writes it", "tcp", "tcp", "h2", ""},
		{"h3 as the panel writes it", "udp", "naive", "h3", ""},
		{"h3 with the stream left on tcp", "udp", "tcp", "h3", ""},
		{"h2 with the stream set to naive", "tcp", "naive", "h2", ""},
		{"h2 with the uTLS chrome fingerprint", "tcp", "tcp", "h2", "chrome"},
		// A dialer opens one wire, so anything that is not udp-only means h2.
		// Omitted and "tcp,udp" both reach that through ParseNetwork reading
		// them as BOTH, not as tcp; a hand-edited config or a share-link import
		// is the likeliest source of either.
		{"h2 with network omitted", "", "tcp", "h2", ""},
		{"h2 with network tcp,udp", "tcp,udp", "tcp", "h2", ""},
		{"h2 with network omitted and the stream set to naive", "", "naive", "h2", ""},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			target := targetServer(t)
			serverPort := tcpserver.PickPort()
			clientPort := tcpserver.PickPort()
			certPEM, keyPEM, pinHex := selfSignedPEM(t)

			startXray(t, `{
				"log": {"loglevel": "error"},
				"inbounds": [{
					"listen": "127.0.0.1",
					"port": `+fmt.Sprint(serverPort)+`,
					"protocol": "naive",
					"settings": `+naiveSettingsJSON()+`,
					"streamSettings": {
						"network": "tcp",
						"security": "tls",
						"tlsSettings": {
							"serverName": "localhost",
							"certificates": [{
								"certificate": `+jsonList(strings.Split(strings.TrimRight(certPEM, "\n"), "\n"))+`,
								"key": `+jsonList(strings.Split(strings.TrimRight(keyPEM, "\n"), "\n"))+`
							}]
						}
					}
				}],
				"outbounds": [{"protocol": "freedom"}]
			}`)
			startXray(t, naiveOutboundClientConfig(uint32(clientPort), uint32(serverPort), c.network, c.streamNetwork, c.alpn, pinHex, c.fingerprint))
			time.Sleep(500 * time.Millisecond)

			client := &http.Client{
				Transport: &http.Transport{
					Proxy: http.ProxyURL(mustURL(fmt.Sprintf("http://127.0.0.1:%d", clientPort))),
				},
				Timeout: 15 * time.Second,
			}
			resp, err := client.Get(target.URL)
			if err != nil {
				t.Fatalf("request through the naive outbound: %v", err)
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			if string(b) != "tunnelled ok" {
				t.Fatalf("body %q, want the target's response", b)
			}
		})
	}
}
