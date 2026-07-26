package forwarder

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"

	cippump "github.com/sagernet/sing-box/transport/masque/connectip/pump"
)

// ConnectIPEgressMode selects server CONNECT-IP dataplane after ASSIGN/ROUTE.
//
//	packet    — RFC 9484 §7.2: relay full IP packets to a TUN/iface (CIP = transport)
//	terminate — lab/app stub: S2 TCP/UDP dial-out (not CIP identity)
const (
	ConnectIPEgressPacket    = "packet"
	ConnectIPEgressTerminate = "terminate"
)

// ResolveConnectIPEgress returns packet|terminate.
// Precedence: MASQUE_CONNECT_IP_EGRESS env → explicit option → default packet.
func ResolveConnectIPEgress(optionValue string) string {
	if v := strings.TrimSpace(os.Getenv("MASQUE_CONNECT_IP_EGRESS")); v != "" {
		return normalizeEgress(v)
	}
	if v := strings.TrimSpace(optionValue); v != "" {
		return normalizeEgress(v)
	}
	return ConnectIPEgressPacket
}

// ConnectIPEgressIsExplicit reports whether egress was set via env or JSON (not bare default).
// Explicit packet must not silently fall back to terminate.
func ConnectIPEgressIsExplicit(optionValue string) bool {
	if strings.TrimSpace(os.Getenv("MASQUE_CONNECT_IP_EGRESS")) != "" {
		return true
	}
	return strings.TrimSpace(optionValue) != ""
}

func normalizeEgress(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case ConnectIPEgressTerminate, "s2", "stub", "dial":
		return ConnectIPEgressTerminate
	default:
		return ConnectIPEgressPacket
	}
}

// RunConnectIPPacketPlaneRelay relays full IP packets between the CONNECT-IP wire
// session and a TunnelDevice (TUN/iface). Demux is nil — raw IP inject (RFC 9484 §6/§7).
// No TCP/UDP terminate. Blocks until ctx cancel or pump error, then closes wire.
func RunConnectIPPacketPlaneRelay(ctx context.Context, wire PacketPlaneConn, device cippump.TunnelDevice) error {
	if wire == nil {
		return errors.New("masque: connect-ip packet plane: nil wire")
	}
	if device == nil {
		return errors.New("masque: connect-ip packet plane: nil device")
	}
	conn := adaptPacketPlaneToPump(wire)
	opts := cippump.UsqueTunnelOptions()
	opts.OnLoopInEnd = func() {
		if f, ok := wire.(packetPlaneCoalescedWriter); ok {
			f.FlushOutgoingDatagramSend()
		}
	}
	return cippump.RunTunnel(ctx, device, conn, opts)
}

// adaptPacketPlaneToPump wraps PacketPlaneConn as pump.PacketConnInPlaceNoWake.
// Always adapt: PacketPlaneConn.ReadPacket([]byte) conflicts with pump.ReadPacket(ctx,[]byte).
func adaptPacketPlaneToPump(wire PacketPlaneConn) cippump.PacketConnInPlaceNoWake {
	return &packetPlanePumpAdapter{wire: wire}
}

type packetPlanePumpAdapter struct {
	wire PacketPlaneConn
}

func (a *packetPlanePumpAdapter) ReadPacket(ctx context.Context, buf []byte) (int, error) {
	if rc, ok := a.wire.(interface {
		ReadPacketWithContext(context.Context, []byte) (int, error)
	}); ok {
		return rc.ReadPacketWithContext(ctx, buf)
	}
	type res struct {
		n   int
		err error
	}
	ch := make(chan res, 1)
	go func() {
		n, err := a.wire.ReadPacket(buf)
		ch <- res{n, err}
	}()
	select {
	case <-ctx.Done():
		return 0, context.Cause(ctx)
	case r := <-ch:
		return r.n, r.err
	}
}

func (a *packetPlanePumpAdapter) WritePacket(buffer []byte) ([]byte, error) {
	return a.wire.WritePacket(buffer)
}

func (a *packetPlanePumpAdapter) WritePacketNoWake(buffer []byte) ([]byte, error) {
	if w, ok := a.wire.(packetPlaneCoalescedWriter); ok {
		return w.WritePacketNoWake(buffer)
	}
	return a.wire.WritePacket(buffer)
}

func (a *packetPlanePumpAdapter) WritePacketInPlaceNoWake(buffer []byte) ([]byte, bool, error) {
	if w, ok := a.wire.(interface {
		WritePacketInPlaceNoWake([]byte) ([]byte, bool, error)
	}); ok {
		return w.WritePacketInPlaceNoWake(buffer)
	}
	icmp, err := a.WritePacketNoWake(buffer)
	return icmp, false, err
}

func (a *packetPlanePumpAdapter) Close() error {
	return a.wire.Close()
}

// IOReadWriterDevice adapts an io.ReadWriteCloser (e.g. sing-tun Tun) to pump.TunnelDevice.
type IOReadWriterDevice struct {
	rwc io.ReadWriteCloser
}

// NewIOReadWriterDevice wraps rwc; nil rwc → nil device.
func NewIOReadWriterDevice(rwc io.ReadWriteCloser) *IOReadWriterDevice {
	if rwc == nil {
		return nil
	}
	return &IOReadWriterDevice{rwc: rwc}
}

func (d *IOReadWriterDevice) ReadPacket(ctx context.Context, buf []byte) (int, error) {
	if d == nil || d.rwc == nil {
		return 0, io.ErrClosedPipe
	}
	type res struct {
		n   int
		err error
	}
	ch := make(chan res, 1)
	go func() {
		n, err := d.rwc.Read(buf)
		ch <- res{n, err}
	}()
	select {
	case <-ctx.Done():
		return 0, context.Cause(ctx)
	case r := <-ch:
		return r.n, r.err
	}
}

func (d *IOReadWriterDevice) WritePacket(pkt []byte) error {
	if d == nil || d.rwc == nil {
		return io.ErrClosedPipe
	}
	_, err := d.rwc.Write(pkt)
	return err
}

func (d *IOReadWriterDevice) Close() error {
	if d == nil || d.rwc == nil {
		return nil
	}
	return d.rwc.Close()
}

// ChannelHandoffDevice is a pure CIP↔peer IP handoff (future L3Router plugs here).
// WritePacket = CIP→peer; ReadPacket = peer→CIP. No routing/ACL.
type ChannelHandoffDevice struct {
	toPeer   chan []byte
	fromPeer chan []byte
	closed   chan struct{}
}

// NewChannelHandoffDevice allocates buffered handoff channels (depth≥1).
func NewChannelHandoffDevice(depth int) *ChannelHandoffDevice {
	if depth < 1 {
		depth = 64
	}
	return &ChannelHandoffDevice{
		toPeer:   make(chan []byte, depth),
		fromPeer: make(chan []byte, depth),
		closed:   make(chan struct{}),
	}
}

// ToPeer returns CIP→peer packets (caller = external L3 consumer).
func (d *ChannelHandoffDevice) ToPeer() <-chan []byte { return d.toPeer }

// InjectFromPeer queues a peer→CIP IP packet.
func (d *ChannelHandoffDevice) InjectFromPeer(pkt []byte) bool {
	cp := append([]byte(nil), pkt...)
	select {
	case <-d.closed:
		return false
	case d.fromPeer <- cp:
		return true
	default:
		return false
	}
}

func (d *ChannelHandoffDevice) ReadPacket(ctx context.Context, buf []byte) (int, error) {
	select {
	case <-ctx.Done():
		return 0, context.Cause(ctx)
	case <-d.closed:
		return 0, io.ErrClosedPipe
	case pkt, ok := <-d.fromPeer:
		if !ok {
			return 0, io.EOF
		}
		return copy(buf, pkt), nil
	}
}

func (d *ChannelHandoffDevice) WritePacket(pkt []byte) error {
	cp := append([]byte(nil), pkt...)
	select {
	case <-d.closed:
		return io.ErrClosedPipe
	case d.toPeer <- cp:
		return nil
	}
}

func (d *ChannelHandoffDevice) Close() error {
	select {
	case <-d.closed:
	default:
		close(d.closed)
	}
	return nil
}
