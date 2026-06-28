package tun

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	cipframe "github.com/sagernet/sing-box/transport/masque/connectip/frame"
	cippump "github.com/sagernet/sing-box/transport/masque/connectip/pump"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
)

// PacketWriter is the CONNECT-IP wire egress from TUN L3 overlay (RFC 9484 datagram plane).
type PacketWriter interface {
	WritePacket(buffer []byte) (icmp []byte, err error)
}

// EgressBatchFlusher completes one R2 egress batch (NoWake enqueue + transport flush).
type EgressBatchFlusher interface {
	FlushEgressBatch()
}

// PacketReader is the CONNECT-IP wire ingress into TUN.
type PacketReader interface {
	ReadPacket(ctx context.Context, buf []byte) (int, error)
}

const l3EgressQueueDepth = 4096

// HostEgressReader reads OS kernel egress from tun (usque Device.ReadPacket parity).
type HostEgressReader func(ctx context.Context, buf []byte) (int, error)

// L3OverlayBridge wires sing-tun L3OverlaySend/Receive to CONNECT-IP without CM TCP dial.
type L3OverlayBridge struct {
	mu            sync.Mutex
	closed        bool
	tunWrite      func([]byte) (int, error)
	hostEgressRead HostEgressReader
	overlayPrefixes []netip.Prefix
	stackInject   func([]byte) error
	writer        PacketWriter
	reader        PacketReader
	nat           OverlayNAT
	shortFlowHook       ShortFlowHook
	flowEgressBytes     atomic.Uint64
	ingressWakeNote     func([]byte)
	ingressAckWakeHook  func()
	shortHookMu         sync.Mutex
	shortHookLast      time.Time
	egressCh            chan []byte
	egressPool          *cippump.NetBuffer
	kernel              *KernelTunDevice
	pumpWake            cippump.WakeHooks
	onLoopInEnd         func()
	outboundDrainHook   func()
}

// NewL3OverlayBridge returns hooks for tun.StackOptions L3OverlaySend plus a receive loop starter.
func NewL3OverlayBridge(tunWrite func([]byte) (int, error), writer PacketWriter, reader PacketReader, nat OverlayNAT) *L3OverlayBridge {
	return &L3OverlayBridge{
		tunWrite:   tunWrite,
		writer:     writer,
		reader:     reader,
		nat:        nat,
		egressCh:   make(chan []byte, l3EgressQueueDepth),
		egressPool: cippump.NewNetBuffer(cippump.DefaultTunnelMTU),
	}
}

// SetHostEgressRead wires usque LoopIn tun read (prod Docker kernel TCP). overlayPrefixes filter wire relay dst.
func (b *L3OverlayBridge) SetHostEgressRead(read HostEgressReader, overlayPrefixes []netip.Prefix) {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.hostEgressRead = read
	if len(overlayPrefixes) > 0 {
		b.overlayPrefixes = append([]netip.Prefix(nil), overlayPrefixes...)
	}
	b.rebuildKernelDeviceLocked()
	b.mu.Unlock()
}

// SetHostIngressWrite registers sing-tun InjectIngressPacket for wire→host delivery (Docker prod).
func (b *L3OverlayBridge) SetHostIngressWrite(write func([]byte) (int, error)) {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.tunWrite = write
	b.rebuildKernelDeviceLocked()
	b.mu.Unlock()
}

// SetStackIngressInject registers connectip netstack inject (synth DialNativeL3TCP path).
func (b *L3OverlayBridge) SetStackIngressInject(inject func([]byte) error) {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.stackInject = inject
	b.mu.Unlock()
}

// SetIngressWakeNote registers CM-parity TCP ACK/DATA wake scheduling on ingress inject.
func (b *L3OverlayBridge) SetIngressWakeNote(note func([]byte)) {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.ingressWakeNote = note
	b.mu.Unlock()
}

// SetIngressAckWakeHook overrides LoopOut batch-end wake (tests); prod uses SetPumpWakeHooks.
func (b *L3OverlayBridge) SetIngressAckWakeHook(hook func()) {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.ingressAckWakeHook = hook
	b.mu.Unlock()
}

// SetPumpWakeHooks configures RunTunnel LoopOut wake (IP-DP-4 unified pump API).
func (b *L3OverlayBridge) SetPumpWakeHooks(wake cippump.WakeHooks, onLoopInEnd func()) {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.pumpWake = wake
	b.onLoopInEnd = onLoopInEnd
	b.mu.Unlock()
}

// SetOutboundDrainHook nudges gVisor egress after ingress ACK wake (TUN L3 parity with CM ScheduleOutboundDrain).
func (b *L3OverlayBridge) SetOutboundDrainHook(hook func()) {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.outboundDrainHook = hook
	b.mu.Unlock()
}

// SetShortFlowHook registers a callback for TCP FIN/RST egress (nc probe parity, P0 native L3).
func (b *L3OverlayBridge) SetShortFlowHook(hook ShortFlowHook) {
	if b == nil {
		return
	}
	b.shortHookMu.Lock()
	b.shortFlowHook = hook
	b.shortHookMu.Unlock()
}

// RebindPacketPlane swaps CONNECT-IP reader/writer after server recycle (W-IP-ARCH-3).
func (b *L3OverlayBridge) RebindPacketPlane(writer PacketWriter, reader PacketReader) {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.writer = writer
	b.reader = reader
	b.mu.Unlock()
}

// Send implements sing-tun L3OverlaySend for gVisor stack egress (synth stackInject path).
// Prod host-kernel relay uses ReadHostEgress in LoopIn; do not enqueue kernel tun reads here.
func (b *L3OverlayBridge) Send(packet []byte) error {
	b.mu.Lock()
	hostEgress := b.hostEgressRead != nil
	closed := b.closed
	b.mu.Unlock()
	if hostEgress {
		return nil
	}
	if closed {
		return net.ErrClosed
	}
	b.mu.Lock()
	ch := b.egressCh
	pool := b.egressPool
	b.mu.Unlock()
	if ch == nil {
		return net.ErrClosed
	}
	var cp []byte
	if pool != nil && len(packet) <= cippump.DefaultTunnelMTU {
		buf := pool.Get()
		n := copy(buf, packet)
		cp = buf[:n]
		b.nat.SNATEgressInPlace(cp)
	} else {
		cp = b.nat.SNATEgress(append([]byte(nil), packet...))
	}
	b.accountFlowEgress(cp)
	b.noteShortFlow(cp)
	select {
	case ch <- cp:
		return nil
	default:
	}
	// Block until LoopIn drains (usque TUN write parity).
	select {
	case ch <- cp:
		return nil
	}
}

func (b *L3OverlayBridge) deliverIngress(out []byte) error {
	if len(out) == 0 {
		return nil
	}
	b.mu.Lock()
	inject := b.stackInject
	tunWrite := b.tunWrite
	b.mu.Unlock()
	// Host kernel (tunWrite) and connectip netstack (stackInject) are mutually exclusive ingress
	// owners. Dual delivery injects orphan SYN-ACK into netstack → RST on wire → server "no session".
	if tunWrite != nil {
		n, err := tunWrite(out)
		if err != nil {
			return err
		}
		if n != len(out) {
			return fmt.Errorf("connect-ip native l3: tunWrite short %d/%d", n, len(out))
		}
		return nil
	}
	if inject != nil {
		return inject(out)
	}
	return nil
}

func (b *L3OverlayBridge) ingressReader() PacketReader {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	return b.reader
}

func (b *L3OverlayBridge) injectIngress(pkt []byte) (hasTCPPayload bool, err error) {
	if len(pkt) == 0 {
		return false, nil
	}
	out := b.nat.DNATIngress(pkt)
	if cipframe.IPv4TCPHasPayload(out) {
		hasTCPPayload = true
	}
	if !b.hostKernelRelay() {
		b.mu.Lock()
		note := b.ingressWakeNote
		b.mu.Unlock()
		if note != nil {
			note(out)
		}
	}
	if err := b.deliverIngress(out); err != nil {
		return hasTCPPayload, err
	}
	if !b.hostKernelRelay() {
		b.flushIngressAckWake()
	}
	return hasTCPPayload, nil
}

func (b *L3OverlayBridge) flushIngressAckWake() {
	b.mu.Lock()
	hook := b.ingressAckWakeHook
	wake := b.pumpWake
	b.mu.Unlock()
	if hook != nil {
		hook()
		return
	}
	cippump.FlushIngressAckWake(b, wake)
}

func (b *L3OverlayBridge) rebuildKernelDeviceLocked() {
	if b.hostEgressRead == nil || b.tunWrite == nil {
		b.kernel = nil
		return
	}
	b.kernel = NewKernelTunDevice(
		b.hostEgressRead,
		b.tunWrite,
		b.nat,
		b.overlayPrefixes,
		func(pkt []byte) {
			b.accountFlowEgress(pkt)
			b.noteShortFlow(pkt)
		},
	)
}

func (b *L3OverlayBridge) tunnelDevice() cippump.TunnelDevice {
	b.mu.Lock()
	kernel := b.kernel
	closed := b.closed
	b.mu.Unlock()
	if closed {
		return nil
	}
	if kernel != nil {
		return kernel
	}
	return b
}

// ReadPacket implements RunTunnel LoopIn (delegates to KernelTunDevice when host-kernel wired).
func (b *L3OverlayBridge) ReadPacket(ctx context.Context, buf []byte) (int, error) {
	b.mu.Lock()
	kernel := b.kernel
	closed := b.closed
	ch := b.egressCh
	b.mu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	if kernel != nil {
		return kernel.ReadPacket(ctx, buf)
	}
	if ch == nil {
		return 0, net.ErrClosed
	}
	select {
	case <-ctx.Done():
		return 0, context.Cause(ctx)
	case pkt, ok := <-ch:
		if !ok {
			return 0, net.ErrClosed
		}
		if len(pkt) > len(buf) {
			return 0, io.ErrShortBuffer
		}
		n := copy(buf, pkt)
		b.releaseEgressPoolSlice(pkt)
		return n, nil
	}
}

func (b *L3OverlayBridge) releaseEgressPoolSlice(pkt []byte) {
	if b == nil || len(pkt) == 0 {
		return
	}
	b.mu.Lock()
	pool := b.egressPool
	b.mu.Unlock()
	if pool != nil {
		pool.Put(pkt[:cap(pkt)])
	}
}

func shouldRelayHostEgress(pkt []byte, prefixes []netip.Prefix, tunHost netip.Addr) bool {
	if len(pkt) < header.IPv4MinimumSize || pkt[0]>>4 != 4 {
		return false
	}
	dst, ok := ipv4Destination(pkt)
	if !ok || !dst.IsValid() || dst == tunHost {
		return false
	}
	if len(prefixes) == 0 {
		return dst.IsGlobalUnicast()
	}
	for _, p := range prefixes {
		if p.IsValid() && p.Contains(dst) {
			return true
		}
	}
	return false
}

// WritePacket injects one CONNECT-IP ingress frame (RunTunnel LoopOut).
func (b *L3OverlayBridge) WritePacket(pkt []byte) error {
	if b.hostKernelRelay() {
		b.mu.Lock()
		kernel := b.kernel
		b.mu.Unlock()
		if kernel != nil {
			return kernel.WritePacket(pkt)
		}
	}
	_, err := b.injectIngress(pkt)
	return err
}

// ScheduleOutboundDrain nudges post-ingress gVisor egress (CM netstack parity).
func (b *L3OverlayBridge) ScheduleOutboundDrain() {
	b.mu.Lock()
	hook := b.outboundDrainHook
	b.mu.Unlock()
	if hook != nil {
		hook()
	}
}

// RunPump runs usque-shaped symmetric pump (LoopIn ‖ LoopOut) until ctx cancel or fatal error.
func (b *L3OverlayBridge) RunPump(ctx context.Context) error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	hasIngress := b.stackInject != nil || b.tunWrite != nil
	hostKernel := b.hostEgressRead != nil
	wake := b.pumpWake
	onLoopInEnd := b.onLoopInEnd
	b.mu.Unlock()
	if !hasIngress {
		return nil
	}
	opts := b.usquePumpOptions(onLoopInEnd)
	if !hostKernel {
		opts.Wake = wake
		opts.OnLoopOutEnd = func(_ cippump.TunnelDevice) {
			b.flushIngressAckWake()
		}
	} else {
		// LoopIn owns ReadHostEgress; sync drain from LoopOut deadlocks on readMu
		// (TestL3OverlayLoopOutDoesNotSyncRelayHostEgress).
		if onLoopInEnd != nil {
			opts.OnLoopInEnd = onLoopInEnd
		} else {
			opts.OnLoopInEnd = func() {
				b.flushIngressAckWake()
			}
		}
	}
	device := b.tunnelDevice()
	if device == nil {
		return net.ErrClosed
	}
	return cippump.RunTunnel(ctx, device, b.packetConn(), opts)
}

func (b *L3OverlayBridge) packetConn() *NativePumpPacketConn {
	hostKernel := b.hostKernelRelay()
	pc := &NativePumpPacketConn{
		Read: func(ctx context.Context, buf []byte) (int, error) {
			b.mu.Lock()
			closed := b.closed
			reader := b.reader
			b.mu.Unlock()
			if closed || reader == nil {
				return 0, net.ErrClosed
			}
			return reader.ReadPacket(ctx, buf)
		},
		Write: func(p []byte) ([]byte, error) {
			b.mu.Lock()
			closed := b.closed
			writer := b.writer
			b.mu.Unlock()
			if closed || writer == nil {
				return nil, net.ErrClosed
			}
			if hostKernel {
				return writeWirePacket(writer, p)
			}
			return writeWirePacketNoWake(writer, p)
		},
	}
	if !hostKernel {
		pc.WriteInPlace = func(p []byte) (bool, []byte, error) {
			b.mu.Lock()
			closed := b.closed
			writer := b.writer
			b.mu.Unlock()
			if closed || writer == nil {
				return false, nil, net.ErrClosed
			}
			return writeWirePacketInPlaceNoWake(writer, p)
		}
	}
	return pc
}

// RunReceiveLoop is deprecated; prod uses RunPump. Kept as alias for tests.
func (b *L3OverlayBridge) RunReceiveLoop(ctx context.Context) error {
	return b.RunPump(ctx)
}

// Close stops L3 overlay bridge.
func (b *L3OverlayBridge) Close() error {
	b.mu.Lock()
	b.closed = true
	ch := b.egressCh
	pool := b.egressPool
	b.egressCh = nil
	b.mu.Unlock()
	if ch != nil {
		close(ch)
		for pkt := range ch {
			if pool != nil {
				pool.Put(pkt[:cap(pkt)])
			}
		}
	}
	return nil
}

// NativePumpPacketConn adapts PacketReader/Writer for pump.RunTunnel when Device is external (TUN L3).
type NativePumpPacketConn struct {
	Read         func(context.Context, []byte) (int, error)
	Write        func([]byte) (icmp []byte, err error)
	WriteInPlace func([]byte) (retained bool, icmp []byte, err error)
	Done         func() error
}

func (p *NativePumpPacketConn) ReadPacket(ctx context.Context, buf []byte) (int, error) {
	if p == nil || p.Read == nil {
		return 0, net.ErrClosed
	}
	return p.Read(ctx, buf)
}

func (p *NativePumpPacketConn) WritePacket(buffer []byte) ([]byte, error) {
	return p.WritePacketNoWake(buffer)
}

func (p *NativePumpPacketConn) WritePacketNoWake(buffer []byte) ([]byte, error) {
	if p == nil || p.Write == nil {
		return nil, net.ErrClosed
	}
	return p.Write(buffer)
}

func (p *NativePumpPacketConn) WritePacketInPlaceNoWake(buffer []byte) (icmp []byte, retained bool, err error) {
	if p != nil && p.WriteInPlace != nil {
		retained, icmp, err = p.WriteInPlace(buffer)
		return icmp, retained, err
	}
	icmp, err = p.WritePacketNoWake(buffer)
	return icmp, false, err
}

func (p *NativePumpPacketConn) Close() error {
	if p != nil && p.Done != nil {
		return p.Done()
	}
	return nil
}

var (
	_ cippump.TunnelDevice         = (*L3OverlayBridge)(nil)
	_ cippump.OutboundDrainDevice  = (*L3OverlayBridge)(nil)
	_ cippump.PacketConn           = (*NativePumpPacketConn)(nil)
	_ cippump.PacketConnNoWake     = (*NativePumpPacketConn)(nil)
	_ cippump.PacketConnInPlaceNoWake = (*NativePumpPacketConn)(nil)
)
