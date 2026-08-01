package naive

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"

	"golang.org/x/net/http2"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/retry"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	naivetransport "github.com/xtls/xray-core/transport/internet/naive"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

var _ proxy.Outbound = (*Client)(nil)

// Client is the naive outbound. It speaks CONNECT over HTTP/2 (through whatever
// TLS the stream settings provide, so Xray's uTLS Chrome fingerprint applies for
// free) or over HTTP/3 (through transport/internet/naive).
type Client struct {
	server        *protocol.ServerSpec
	policyManager policy.Manager
	useH3         bool
}

// NewClient creates a new naive outbound handler.
func NewClient(ctx context.Context, config *ClientConfig) (*Client, error) {
	if config.Server == nil {
		return nil, errors.New("no target server found")
	}
	server, err := protocol.NewServerSpecFromPB(config.Server)
	if err != nil {
		return nil, errors.New("failed to get server spec").Base(err)
	}
	if server.User == nil {
		return nil, errors.New("naive: server has no user")
	}

	tcp, udp := naivetransport.ParseNetwork(config.Network)
	// A single outbound dials one wire; "udp" (h3) only when it is asked for
	// explicitly, since h2 is what a "https://" naive URI means.
	useH3 := udp && !tcp

	v := core.MustFromContext(ctx)
	return &Client{
		server:        server,
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		useH3:         useH3,
	}, nil
}

func (c *Client) requestHeader(account *MemoryAccount, username, authority string) http.Header {
	header := http.Header{}
	header.Set(headerProxyAuthorization, "Basic "+base64.StdEncoding.EncodeToString([]byte(username+":"+account.Password)))
	header.Set(headerPadding, RequestPaddingHeader())
	header.Set(headerPaddingTypeRequest, "1, 0")
	// Cronet sends the authority twice; matching it keeps our request shape
	// indistinguishable from the reference client.
	header.Set(headerConnectAuthority, authority)
	return header
}

// Process implements proxy.Outbound.
func (c *Client) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("target not specified")
	}
	ob.Name = "naive"
	ob.CanSpliceCopy = 3
	destination := ob.Target

	if destination.Network == net.Network_UDP {
		return errors.New("naive: UDP is not supported, naive is an HTTP CONNECT proxy")
	}

	user := c.server.User
	account, ok := user.Account.(*MemoryAccount)
	if !ok {
		return errors.New("naive: user account is not valid")
	}
	authority := destination.NetAddr()
	// The remote server decides what the Basic username means, so send its
	// username when the config carries one and the email otherwise. Our own
	// inbound accepts both spellings.
	header := c.requestHeader(account, BasicUsername(user), authority)

	var (
		conn         stat.Connection
		reader       io.Reader
		writer       io.Writer
		halfClose    func()
		closeFuncs   []func()
		responseHead http.Header
	)
	defer func() {
		for i := len(closeFuncs) - 1; i >= 0; i-- {
			closeFuncs[i]()
		}
	}()

	if c.useH3 {
		request := &naivetransport.ConnectRequest{Authority: authority, Header: header}
		dialCtx := naivetransport.ContextWithConnectRequest(ctx, request)
		err := retry.ExponentialBackoff(5, 100).On(func() error {
			rawConn, err := dialer.Dial(dialCtx, c.server.Destination)
			if err != nil {
				return err
			}
			conn = rawConn
			return nil
		})
		if err != nil {
			return errors.New("naive: failed to find an available destination").AtWarning().Base(err)
		}
		closeFuncs = append(closeFuncs, func() { conn.Close() })
		if request.StatusCode != http.StatusOK {
			return errors.New("naive: server rejected CONNECT with status ", request.StatusCode)
		}
		responseHead = request.Response
		reader = conn
		writer = conn
		if cw, ok := conn.(interface{ CloseWrite() error }); ok {
			halfClose = func() { cw.CloseWrite() }
		}
	} else {
		err := retry.ExponentialBackoff(5, 100).On(func() error {
			rawConn, err := dialer.Dial(ctx, c.server.Destination)
			if err != nil {
				return err
			}
			conn = rawConn
			return nil
		})
		if err != nil {
			return errors.New("naive: failed to find an available destination").AtWarning().Base(err)
		}
		closeFuncs = append(closeFuncs, func() { conn.Close() })

		if tlsConn, ok := conn.(tls.Interface); ok {
			if alpn := tlsConn.NegotiatedProtocol(); alpn != "" && alpn != "h2" {
				return errors.New(`naive: server negotiated ALPN "`, alpn, `", set "alpn": ["h2"] in tlsSettings`)
			}
		}

		requestBody, requestWriter := io.Pipe()
		closeFuncs = append(closeFuncs, func() { requestWriter.Close() })

		request := &http.Request{
			Method: http.MethodConnect,
			URL:    &url.URL{Scheme: "https", Host: authority},
			Host:   authority,
			Header: header,
			Body:   requestBody,
		}
		request = request.WithContext(ctx)

		clientConn, err := (&http2.Transport{}).NewClientConn(conn)
		if err != nil {
			return errors.New("naive: failed to start HTTP/2").Base(err)
		}
		response, err := clientConn.RoundTrip(request)
		if err != nil {
			return errors.New("naive: CONNECT failed").Base(err)
		}
		closeFuncs = append(closeFuncs, func() { response.Body.Close() })
		if response.StatusCode != http.StatusOK {
			return errors.New("naive: server rejected CONNECT with status ", response.Status)
		}
		responseHead = response.Header
		reader = response.Body
		writer = requestWriter
		halfClose = func() { requestWriter.Close() }
	}

	errors.LogInfo(ctx, "naive: tunneling request to ", destination, " via ", c.server.Destination.NetAddr())

	paddingType, err := NegotiateClientPadding(responseHead)
	if err != nil {
		return err
	}
	if paddingType == PaddingTypeVariant1 {
		reader = newPaddingReader(reader)
		writer = newPaddingWriter(writer)
	}

	sessionPolicy := c.policyManager.ForLevel(user.Level)
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, sessionPolicy.Timeouts.ConnectionIdle)

	requestDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
		err := buf.Copy(link.Reader, buf.NewWriter(writer), buf.UpdateActivity(timer))
		// Half-close so the far end sees EOF while the downlink keeps running.
		if halfClose != nil {
			halfClose()
		}
		return err
	}
	responseDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
		return buf.Copy(buf.NewReader(reader), link.Writer, buf.UpdateActivity(timer))
	}

	if err := task.Run(ctx, requestDone, responseDone); err != nil {
		return errors.New("naive: connection ends").Base(err)
	}
	return nil
}

func init() {
	common.Must(common.RegisterConfig((*ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewClient(ctx, config.(*ClientConfig))
	}))
}
