package tuic

import (
	"bytes"
	"context"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	tuictransport "github.com/xtls/xray-core/transport/internet/tuic"
)

func init() {
	common.Must(common.RegisterConfig((*ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewOutbound(ctx, config.(*ClientConfig))
	}))
}

// Outbound is the TUIC outbound handler.
type Outbound struct {
	config        *ClientConfig
	destination   net.Destination
	settings      tuictransport.ClientSettings
	policyManager policy.Manager
}

// NewOutbound creates a new TUIC outbound handler.
func NewOutbound(ctx context.Context, config *ClientConfig) (*Outbound, error) {
	if config == nil {
		return nil, errors.New("TUIC outbound config is nil")
	}
	if len(config.Server) == 0 {
		return nil, errors.New("TUIC: no server specified")
	}

	endpoint := config.Server[0]
	if endpoint.User == nil {
		return nil, errors.New("TUIC: no user specified for server")
	}
	memoryUser, err := endpoint.User.ToMemoryUser()
	if err != nil {
		return nil, errors.New("TUIC: failed to parse user").Base(err)
	}
	account, ok := memoryUser.Account.(*MemoryAccount)
	if !ok {
		return nil, errors.New("TUIC: invalid account type")
	}

	heartbeat := time.Duration(config.GetHeartbeat()) * time.Second
	if heartbeat <= 0 {
		heartbeat = 10 * time.Second
	}

	v := core.MustFromContext(ctx)
	return &Outbound{
		config: config,
		// internet.Dial routes on the destination's network, not on the transport,
		// so a UDP destination here would silently bypass the tuic transport and
		// hand back a bare UDP socket. The transport opens the real UDP socket
		// itself, exactly like hysteria.
		destination: net.TCPDestination(endpoint.Address.AsAddress(), net.Port(endpoint.Port)),
		settings: tuictransport.ClientSettings{
			UUID:              account.UUID,
			Password:          account.Password,
			CongestionControl: config.GetCongestionControl(),
			UDPStream:         config.GetUdpStream(),
			ZeroRTTHandshake:  config.GetZeroRttHandshake(),
			Heartbeat:         heartbeat,
		},
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
	}, nil
}

// Process relays one connection through the TUIC server.
func (o *Outbound) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		return errors.New("TUIC: no outbound in context")
	}
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("TUIC: target not specified")
	}
	ob.Name = "tuic"
	ob.CanSpliceCopy = 3
	target := ob.Target

	// Credentials live in the proxy's settings, so the transport dialer can only
	// learn them through the context. Same direction of travel as the inbound's
	// Authenticator, just the other way round.
	dialCtx := tuictransport.ContextWithClientSettings(ctx, o.settings)
	dialCtx = tuictransport.ContextWithRequireDatagram(dialCtx, target.Network == net.Network_UDP)

	conn, err := dialer.Dial(dialCtx, o.destination)
	if err != nil {
		return errors.New("TUIC: failed to connect to ", o.destination).Base(err)
	}
	defer conn.Close()

	errors.LogInfo(ctx, "tunneling request to ", target, " via tuic:", o.destination.NetAddr())

	sessionPolicy := o.policyManager.ForLevel(0)
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, sessionPolicy.Timeouts.ConnectionIdle)

	if target.Network == net.Network_UDP {
		packetConn, ok := stat.TryUnwrapStatsConn(conn).(tuictransport.PacketConn)
		if !ok {
			return errors.New("TUIC: transport did not return a packet connection for a UDP target")
		}
		return o.processUDP(ctx, link, packetConn, target, timer, sessionPolicy)
	}
	return o.processTCP(ctx, link, conn, target, timer, sessionPolicy)
}

func (o *Outbound) processTCP(
	ctx context.Context,
	link *transport.Link,
	conn stat.Connection,
	target net.Destination,
	timer *signal.ActivityTimer,
	sessionPolicy policy.Session,
) error {
	requestDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
		// [version, Connect, address]. The server replies with raw payload, there
		// is no response header to read back.
		header := bytes.NewBuffer(make([]byte, 0, 2+260))
		header.WriteByte(tuictransport.TUICVersion)
		header.WriteByte(tuictransport.TUICCommandConnect)
		if err := tuictransport.WriteDestination(header, target); err != nil {
			return errors.New("failed to encode TUIC destination").Base(err)
		}
		if _, err := conn.Write(header.Bytes()); err != nil {
			return errors.New("failed to write TUIC connect header").Base(err)
		}
		return buf.Copy(link.Reader, buf.NewWriter(conn), buf.UpdateActivity(timer))
	}

	responseDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
		return buf.Copy(buf.NewReader(conn), link.Writer, buf.UpdateActivity(timer))
	}

	if err := task.Run(ctx, task.OnSuccess(requestDone, task.Close(link.Writer)), responseDone); err != nil {
		return errors.New("TUIC connection ends").Base(err)
	}
	return nil
}

func (o *Outbound) processUDP(
	ctx context.Context,
	link *transport.Link,
	packetConn tuictransport.PacketConn,
	target net.Destination,
	timer *signal.ActivityTimer,
	sessionPolicy policy.Session,
) error {
	requestDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
		return buf.Copy(link.Reader, &udpPacketWriter{conn: packetConn, destination: target}, buf.UpdateActivity(timer))
	}

	responseDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
		return buf.Copy(&udpPacketReader{conn: packetConn}, link.Writer, buf.UpdateActivity(timer))
	}

	if err := task.Run(ctx, task.OnSuccess(requestDone, task.Close(link.Writer)), responseDone); err != nil {
		return errors.New("TUIC UDP connection ends").Base(err)
	}
	return nil
}
