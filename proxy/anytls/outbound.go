package anytls

import (
	"context"
	gonet "net"
	"sync"
	"time"

	singanytls "github.com/anytls/sing-anytls"
	"github.com/anytls/sing-anytls/util"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/singbridge"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

func init() {
	common.Must(common.RegisterConfig((*ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewClient(ctx, config.(*ClientConfig))
	}))
}

// Outbound is an outbound connection handler that speaks the anytls protocol.
type Outbound struct {
	ctx    context.Context
	server net.Destination
	config *ClientConfig

	access sync.Mutex
	client *singanytls.Client
	dialer internet.Dialer
}

func NewClient(ctx context.Context, config *ClientConfig) (*Outbound, error) {
	if config.Address == nil {
		return nil, errors.New("anytls server address is not set")
	}
	if config.Port == 0 {
		return nil, errors.New("invalid anytls port")
	}
	if config.Password == "" {
		return nil, errors.New("anytls password is not specified")
	}
	return &Outbound{
		ctx: ctx,
		server: net.Destination{
			Address: config.Address.AsAddress(),
			Port:    net.Port(config.Port),
			Network: net.Network_TCP,
		},
		config: config,
	}, nil
}

// getClient lazily builds the session client around the dialer Xray hands to
// Process. The dialer is a property of the outbound handler rather than of a
// single request, but it is only available from Process, and it is replaced
// whenever the handler is rebuilt, so the client is rebuilt with it.
func (o *Outbound) getClient(dialer internet.Dialer) (*singanytls.Client, error) {
	o.access.Lock()
	defer o.access.Unlock()

	if o.client != nil && o.dialer == dialer {
		return o.client, nil
	}
	if o.client != nil {
		o.client.Close()
		o.client = nil
	}

	client, err := singanytls.NewClient(core.ToBackgroundDetachedContext(o.ctx), singanytls.ClientConfig{
		Password:                 o.config.Password,
		IdleSessionCheckInterval: time.Duration(o.config.IdleSessionCheckInterval) * time.Second,
		IdleSessionTimeout:       time.Duration(o.config.IdleSessionTimeout) * time.Second,
		MinIdleSession:           int(o.config.MinIdleSession),
		DisableReuse:             o.config.DisableReuse,
		DialOut:                  o.dialOut(dialer),
		Logger:                   singbridge.NewLogger(errors.New),
	})
	if err != nil {
		return nil, errors.New("failed to create anytls client").Base(err)
	}
	o.client = client
	o.dialer = dialer
	return client, nil
}

func (o *Outbound) dialOut(dialer internet.Dialer) util.DialOutFunc {
	return func(context.Context) (gonet.Conn, error) {
		// Deliberately not the caller's context. A session outlives the request
		// that happened to open it and is then reused by others, so tying its
		// underlying connection to that first request would tear the session down
		// under everyone else (and, with proxySettings, kill the dialer-proxy
		// goroutine outright).
		ctx := core.ToBackgroundDetachedContext(o.ctx)
		ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{
			Target:        o.server,
			Name:          "anytls",
			CanSpliceCopy: 3,
		}})
		conn, err := dialer.Dial(ctx, o.server)
		if err != nil {
			return nil, errors.New("failed to connect to anytls server").Base(err)
		}
		return conn, nil
	}
}

// Process implements proxy.Outbound.Process().
func (o *Outbound) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("target not specified")
	}
	ob.Name = "anytls"
	ob.CanSpliceCopy = 3
	destination := ob.Target

	client, err := o.getClient(dialer)
	if err != nil {
		return err
	}

	errors.LogInfo(ctx, "tunneling request to ", destination, " via ", o.server.NetAddr())

	var inboundConn net.Conn
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		inboundConn = inbound.Conn
	}

	if session.TimeoutOnlyFromContext(ctx) {
		ctx = context.WithoutCancel(ctx)
	}

	if destination.Network == net.Network_UDP {
		// anytls carries no UDP, so it goes out as UDP-over-TCP the same way the
		// inbound expects to receive it.
		stream, err := client.CreateProxy(ctx, uot.RequestDestination(uot.Version))
		if err != nil {
			return errors.New("failed to create anytls stream").Base(err)
		}
		uConn := uot.NewLazyConn(stream, uot.Request{
			IsConnect:   true,
			Destination: singbridge.ToSocksaddr(destination),
		})

		var packetConn N.PacketConn
		if pc, isPacketConn := inboundConn.(N.PacketConn); isPacketConn {
			packetConn = pc
		} else if nc, isNetPacket := inboundConn.(net.PacketConn); isNetPacket {
			packetConn = bufio.NewPacketConn(nc)
		} else {
			packetConn = &singbridge.PacketConnWrapper{
				Reader: link.Reader,
				Writer: link.Writer,
				Conn:   inboundConn,
				Dest:   destination,
			}
		}
		return singbridge.ReturnError(bufio.CopyPacketConn(ctx, packetConn, uConn))
	}

	stream, err := client.CreateProxy(ctx, singbridge.ToSocksaddr(destination))
	if err != nil {
		return errors.New("failed to create anytls stream").Base(err)
	}
	return singbridge.CopyConn(ctx, inboundConn, link, stream)
}
