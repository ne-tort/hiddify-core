package tun

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	cipframe "github.com/sagernet/sing-box/transport/masque/connectip/frame"
	"github.com/sagernet/sing-box/transport/masque/connectip/losslocus"
	cippump "github.com/sagernet/sing-box/transport/masque/connectip/pump"
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

// l3EgressQueueDepth sizes the stack/synth Send→LoopIn queue only.
// Prod host-kernel path (hostEgressRead set) never enqueues here — Send is no-op and
// LoopIn reads KernelTunDevice / ReadHostEgress (P2-8 LOCK: idle ~96KiB headers, not packet double-buffer).
const l3EgressQueueDepth = 4096

// HostEgressReader reads OS kernel egress from tun (usque Device.ReadPacket parity).
type HostEgressReader func(ctx context.Context, buf []byte) (int, error)

// L3OverlayBridge wires sing-tun L3OverlaySend/Receive to CONNECT-IP without CM TCP dial.
type L3OverlayBridge struct {
	mu             sync.Mutex
	closed         atomic.Bool
	tunWrite       func([]byte) (int, error)
	hostEgressRead HostEgressReader
	hostEgressBatch HostEgressBatchReader
	overlayPrefixes []netip.Prefix
	stackInject    func([]byte) error
	// planeWriter/planeReader are atomic so LoopIn/LoopOut hot path avoids mu.Lock per datagram.
	// RebindPacketPlane publishes new values; Close sets closed.
	planeWriter atomic.Value // PacketWriter
	planeReader atomic.Value // PacketReader
	nat                 OverlayNAT
	shortFlowHook       ShortFlowHook
	flowEgressBytes     atomic.Uint64
	ingressWakeNote     func([]byte)
	ingressAckWakeHook  func()
	shortHookMu         sync.Mutex
	shortHookLast       time.Time
	egressCh            chan []byte
	egressPool          *cippump.NetBuffer
	kernel              *KernelTunDevice
	pumpWake            cippump.WakeHooks
	onLoopInEnd         func()
	outboundDrainHook   func()
	loopInMaxBatch      int // 0 → DefaultLoopInMaxBatch; H2 host-kernel uses H2HostKernelLoopInMaxBatch
}

// NewL3OverlayBridge returns hooks for tun.StackOptions L3OverlaySend plus a receive loop starter.
// egressCh is allocated lazily for gVisor/synth Send→LoopIn; host-kernel path never needs it (P6-S3).
func NewL3OverlayBridge(tunWrite func([]byte) (int, error), writer PacketWriter, reader PacketReader, nat OverlayNAT) *L3OverlayBridge {
	b := &L3OverlayBridge{
		tunWrite:   tunWrite,
		nat:        nat,
		egressPool: cippump.DefaultNetBuffer(),
	}
	if writer != nil {
		b.planeWriter.Store(writer)
	}
	if reader != nil {
		b.planeReader.Store(reader)
	}
	return b
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
	// Host-kernel LoopIn reads OS tun; drop idle egressCh (~96KiB headers) — Send is no-op here.
	b.egressCh = nil
	b.rebuildKernelDeviceLocked()
	b.mu.Unlock()
}

// SetHostEgressBatch wires NativeTun ReadHostEgressBatch (VNetHdr upload DoD path).
func (b *L3OverlayBridge) SetHostEgressBatch(batch HostEgressBatchReader) {
	if b == nil || batch == nil {
		return
	}
	b.mu.Lock()
	b.hostEgressBatch = batch
	if b.kernel != nil {
		b.kernel.SetHostEgressBatch(batch)
	}
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

// SetLoopInMaxBatch overrides host-kernel RunTunnelBatch depth (0 restores DefaultLoopInMaxBatch).
func (b *L3OverlayBridge) SetLoopInMaxBatch(n int) {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.loopInMaxBatch = n
	b.mu.Unlock()
}

func (b *L3OverlayBridge) loopInMaxBatchOrDefault() int {
	if b == nil {
		return cippump.DefaultLoopInMaxBatch
	}
	b.mu.Lock()
	n := b.loopInMaxBatch
	b.mu.Unlock()
	if n > 0 {
		return n
	}
	return cippump.DefaultLoopInMaxBatch
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
	if writer != nil {
		b.planeWriter.Store(writer)
	}
	if reader != nil {
		b.planeReader.Store(reader)
	}
}

func (b *L3OverlayBridge) loadWriter() PacketWriter {
	if v := b.planeWriter.Load(); v != nil {
		if w, ok := v.(PacketWriter); ok {
			return w
		}
	}
	return nil
}

func (b *L3OverlayBridge) loadReader() PacketReader {
	if v := b.planeReader.Load(); v != nil {
		if r, ok := v.(PacketReader); ok {
			return r
		}
	}
	return nil
}

// Send implements sing-tun L3OverlaySend for gVisor stack egress (synth stackInject path).
// Prod host-kernel relay uses ReadHostEgress in LoopIn; do not enqueue kernel tun reads here.
func (b *L3OverlayBridge) Send(packet []byte) error {
	b.mu.Lock()
	hostEgress := b.hostEgressRead != nil
	b.mu.Unlock()
	if hostEgress {
		return nil
	}
	if b.closed.Load() {
		return net.ErrClosed
	}
	b.mu.Lock()
	ch := b.egressCh
	if ch == nil && !b.closed.Load() {
		ch = make(chan []byte, l3EgressQueueDepth)
		b.egressCh = ch
	}
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
			losslocus.RecordTunWriteFail()
			// Transient host TUN backpressure must not kill LoopOut / whole plane
			// (AUD-29): drop this IP datagram; siblings keep the plane.
			if isTransientTunWriteErr(err) {
				return nil
			}
			return err
		}
		if n != len(out) {
			losslocus.RecordTunWriteShort()
			// Short write under pressure: drop, keep plane (same isolation goal).
			return nil
		}
		return nil
	}
	if inject != nil {
		return inject(out)
	}
	losslocus.RecordTunNoConsumer()
	return nil
}

func isTransientTunWriteErr(err error) bool {
	if err == nil {
		return false
	}
	if ne, ok := err.(net.Error); ok && ne.Temporary() {
		return true
	}
	low := strings.ToLower(err.Error())
	return strings.Contains(low, "no buffer space") ||
		strings.Contains(low, "enobufs") ||
		strings.Contains(low, "resource temporarily") ||
		strings.Contains(low, "temporar") ||
		strings.Contains(low, "would block") ||
		strings.Contains(low, "eagain")
}

func (b *L3OverlayBridge) ingressReader() PacketReader {
	if b == nil || b.closed.Load() {
		return nil
	}
	return b.loadReader()
}

func (b *L3OverlayBridge) noteIngressWake(out []byte) {
	if len(out) == 0 {
		return
	}
	b.mu.Lock()
	note := b.ingressWakeNote
	b.mu.Unlock()
	if note != nil {
		note(out)
	}
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
		b.noteIngressWake(out)
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
	if b.hostEgressBatch != nil && b.kernel != nil {
		b.kernel.SetHostEgressBatch(b.hostEgressBatch)
	}
}

func (b *L3OverlayBridge) tunnelDevice() cippump.TunnelDevice {
	if b.closed.Load() {
		return nil
	}
	b.mu.Lock()
	kernel := b.kernel
	b.mu.Unlock()
	if kernel != nil {
		return kernel
	}
	return b
}

// ReadPacket implements RunTunnel LoopIn (delegates to KernelTunDevice when host-kernel wired).
func (b *L3OverlayBridge) ReadPacket(ctx context.Context, buf []byte) (int, error) {
	if b.closed.Load() {
		return 0, net.ErrClosed
	}
	b.mu.Lock()
	kernel := b.kernel
	ch := b.egressCh
	b.mu.Unlock()
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

// WritePacket injects one CONNECT-IP ingress frame (RunTunnel LoopOut).
func (b *L3OverlayBridge) WritePacket(pkt []byte) error {
	if b.hostKernelRelay() {
		b.mu.Lock()
		kernel := b.kernel
		b.mu.Unlock()
		if kernel != nil {
			b.noteIngressWake(pkt)
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
	}
	// host-kernel prod: RunTunnelBatch + LoopOut AckWake/OnLoopInEnd flush (upload batch extension over usque).
	device := b.tunnelDevice()
	if device == nil {
		return net.ErrClosed
	}
	conn := b.packetConn()
	if hostKernel {
		batchDev, ok := device.(cippump.BatchTunnelDevice)
		if !ok {
			return errors.New("connect-ip: host-kernel pump requires BatchTunnelDevice")
		}
		batchOpts := b.hostKernelBatchPumpOptions(onLoopInEnd)
		batchOpts.Wake = wake
		batchOpts.OnLoopOutEnd = func(_ cippump.TunnelDevice) {
			b.flushIngressAckWake()
		}
		return cippump.RunTunnelBatch(ctx, batchDev, conn, batchOpts, b.loopInMaxBatchOrDefault())
	}
	return cippump.RunTunnel(ctx, device, conn, opts)
}

func (b *L3OverlayBridge) packetConn() *NativePumpPacketConn {
	hostKernel := b.hostKernelRelay()
	pc := &NativePumpPacketConn{
		Read: func(ctx context.Context, buf []byte) (int, error) {
			if b.closed.Load() {
				return 0, net.ErrClosed
			}
			reader := b.loadReader()
			if reader == nil {
				return 0, net.ErrClosed
			}
			return reader.ReadPacket(ctx, buf)
		},
		Write: func(p []byte) ([]byte, error) {
			if b.closed.Load() {
				return nil, net.ErrClosed
			}
			writer := b.loadWriter()
			if writer == nil {
				return nil, net.ErrClosed
			}
			if hostKernel {
				return writeHostKernelEgressWire(writer, p)
			}
			return writeWirePacketNoWake(writer, p)
		},
	}
	if hostKernel {
		pc.WriteInPlace = func(p []byte) (bool, []byte, error) {
			if b.closed.Load() {
				return false, nil, net.ErrClosed
			}
			writer := b.loadWriter()
			if writer == nil {
				return false, nil, net.ErrClosed
			}
			return writeHostKernelEgressInPlace(writer, p)
		}
	} else {
		pc.WriteInPlace = func(p []byte) (bool, []byte, error) {
			if b.closed.Load() {
				return false, nil, net.ErrClosed
			}
			writer := b.loadWriter()
			if writer == nil {
				return false, nil, net.ErrClosed
			}
			return writeWirePacketInPlaceNoWake(writer, p)
		}
	}
	return pc
}

// Close stops L3 overlay bridge.
func (b *L3OverlayBridge) Close() error {
	b.closed.Store(true)
	b.mu.Lock()
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
	if p == nil || p.Write == nil {
		return nil, net.ErrClosed
	}
	return p.Write(buffer)
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
