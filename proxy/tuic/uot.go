package tuic

import (
	"context"
	"encoding/binary"
	"io"
	"net/netip"

	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// UDP-over-TCP (UoT). sing-box and Hiddify clients configured with
// `udp_over_stream: true` do not use TUIC's own UDP carriers at all: they open a
// normal TUIC Connect stream to the magic host sp.v2.udp-over-tcp.arpa and frame
// UDP inside it. A server that does not recognise the magic host tries to open a
// TCP connection to a domain that does not resolve, so that cohort gets working
// TCP and 100% dead UDP with no error a user can act on.

// uotVersionOf reports the UoT version a Connect destination is asking for.
func uotVersionOf(destination net.Destination) (int, bool) {
	if !destination.IsValid() || !destination.Address.Family().IsDomain() {
		return 0, false
	}
	switch destination.Address.Domain() {
	case uot.MagicAddress:
		return uot.Version, true
	case uot.LegacyMagicAddress:
		return uot.LegacyVersion, true
	default:
		return 0, false
	}
}

// processUoT relays a UoT stream. The inner destination is dispatched as UDP, so
// routing, sniffing and the per-user counters see it as the UDP traffic it is.
func (i *Inbound) processUoT(ctx context.Context, conn stat.Connection, version int, dispatcher routing.Dispatcher) error {
	var (
		isConnect bool
		fixedDest net.Destination
	)
	// Version 1 has no request header at all: every packet carries its address.
	if version == uot.Version {
		request, err := uot.ReadRequest(conn)
		if err != nil {
			return errors.New("failed to read UoT request").Base(err)
		}
		isConnect = request.IsConnect
		fixedDest = destinationFromSocksaddr(request.Destination)
		if isConnect && !fixedDest.IsValid() {
			return errors.New("invalid UoT connect destination")
		}
	}

	reader := &uotReader{conn: conn, isConnect: isConnect, destination: fixedDest}

	target := fixedDest
	if !isConnect {
		// Without a fixed destination there is nothing to route on until the
		// first packet arrives, so peek it and hand it back on the first read.
		first, err := reader.readPacket()
		if err != nil {
			return errors.New("failed to read first UoT packet").Base(err)
		}
		if first.UDP == nil || !first.UDP.IsValid() {
			first.Release()
			return errors.New("invalid UoT packet destination")
		}
		target = *first.UDP
		reader.pending = buf.MultiBuffer{first}
	}

	email := ""
	if inbound := session.InboundFromContext(ctx); inbound != nil && inbound.User != nil {
		email = inbound.User.Email
	}
	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   conn.RemoteAddr(),
		To:     target,
		Status: log.AccessAccepted,
		Email:  email,
	})
	errors.LogDebug(ctx, "accepted TUIC UoT (v", version, ") connection to ", target, " user: ", email)

	return dispatcher.DispatchLink(ctx, target, &transport.Link{
		Reader: reader,
		Writer: &uotWriter{conn: conn, isConnect: isConnect, destination: fixedDest},
	})
}

type uotReader struct {
	conn        io.Reader
	isConnect   bool
	destination net.Destination
	pending     buf.MultiBuffer
}

func (r *uotReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if len(r.pending) > 0 {
		mb := r.pending
		r.pending = nil
		return mb, nil
	}
	buffer, err := r.readPacket()
	if err != nil {
		return nil, err
	}
	return buf.MultiBuffer{buffer}, nil
}

func (r *uotReader) readPacket() (*buf.Buffer, error) {
	destination := r.destination
	if !r.isConnect {
		address, err := uot.AddrParser.ReadAddrPort(r.conn)
		if err != nil {
			return nil, err
		}
		destination = destinationFromSocksaddr(address)
		if !destination.IsValid() {
			return nil, errors.New("invalid UoT packet address")
		}
	}
	var length uint16
	if err := binary.Read(r.conn, binary.BigEndian, &length); err != nil {
		return nil, err
	}
	var buffer *buf.Buffer
	if int32(length) > buf.Size {
		buffer = buf.NewWithSize(int32(length))
	} else {
		buffer = buf.New()
	}
	if length > 0 {
		if _, err := buffer.ReadFullFrom(r.conn, int32(length)); err != nil {
			buffer.Release()
			return nil, err
		}
	}
	buffer.UDP = &destination
	return buffer, nil
}

type uotWriter struct {
	conn        io.Writer
	isConnect   bool
	destination net.Destination
}

func (w *uotWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	for _, buffer := range mb {
		destination := w.destination
		if buffer.UDP != nil {
			destination = *buffer.UDP
		}
		if !w.isConnect && !destination.IsValid() {
			continue
		}
		if err := w.writePacket(buffer.Bytes(), destination); err != nil {
			return err
		}
	}
	return nil
}

func (w *uotWriter) writePacket(payload []byte, destination net.Destination) error {
	// One Write per packet: a split header would be a separate stream frame and
	// UoT has no way to resynchronise if a peer reads a partial header.
	address := socksaddrFromDestination(destination)
	headerLen := 2
	if !w.isConnect {
		headerLen += uot.AddrParser.AddrPortLen(address)
	}
	out := buf.NewWithSize(int32(headerLen + len(payload)))
	defer out.Release()
	if !w.isConnect {
		if err := uot.AddrParser.WriteAddrPort(out, address); err != nil {
			return err
		}
	}
	if err := binary.Write(out, binary.BigEndian, uint16(len(payload))); err != nil {
		return err
	}
	if _, err := out.Write(payload); err != nil {
		return err
	}
	_, err := w.conn.Write(out.Bytes())
	return err
}

func destinationFromSocksaddr(address M.Socksaddr) net.Destination {
	if address.Port == 0 {
		return net.Destination{}
	}
	if address.IsFqdn() {
		return net.UDPDestination(net.DomainAddress(address.Fqdn), net.Port(address.Port))
	}
	if !address.Addr.IsValid() {
		return net.Destination{}
	}
	return net.UDPDestination(net.IPAddress(address.Addr.Unmap().AsSlice()), net.Port(address.Port))
}

func socksaddrFromDestination(destination net.Destination) M.Socksaddr {
	if !destination.IsValid() {
		return M.Socksaddr{}
	}
	if destination.Address.Family().IsDomain() {
		return M.Socksaddr{Fqdn: destination.Address.Domain(), Port: uint16(destination.Port)}
	}
	address, ok := netip.AddrFromSlice(destination.Address.IP())
	if !ok {
		return M.Socksaddr{}
	}
	return M.SocksaddrFrom(address.Unmap(), uint16(destination.Port))
}
