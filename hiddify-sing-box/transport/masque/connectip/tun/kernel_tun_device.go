package tun

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"sync"
	"time"

	cippump "github.com/sagernet/sing-box/transport/masque/connectip/pump"
)

// KernelTunDevice is usque TunnelDevice for prod host-kernel path:
// ReadPacket = readMu + ReadHostEgress + SNAT + prefix filter;
// WritePacket = DNAT + WriteIngress (fatal on err, usque WaterAdapter parity).
type KernelTunDevice struct {
	readMu          sync.Mutex
	read            HostEgressReader
	readBatch       HostEgressBatchReader
	write           func([]byte) (int, error)
	nat             OverlayNAT
	overlayPrefixes []netip.Prefix
	onEgress        func([]byte)
	readObs         *HostKernelReadObserver // tests/diagnostics only
}

// NewKernelTunDevice wires host tun fd read/write with overlay NAT.
func NewKernelTunDevice(
	read HostEgressReader,
	write func([]byte) (int, error),
	nat OverlayNAT,
	overlayPrefixes []netip.Prefix,
	onEgress func([]byte),
) *KernelTunDevice {
	if read == nil || write == nil {
		return nil
	}
	d := &KernelTunDevice{
		read:            read,
		write:           write,
		nat:             nat,
		overlayPrefixes: append([]netip.Prefix(nil), overlayPrefixes...),
		onEgress:        onEgress,
	}
	d.readBatch = hostEgressSingleBatch{d: d}
	return d
}

// AttachReadObserver wires optional read metrics (tests only; nil in prod).
func (d *KernelTunDevice) AttachReadObserver(obs *HostKernelReadObserver) {
	if d == nil {
		return
	}
	d.readObs = obs
}

// ReadObserver returns the attached read observer, if any.
func (d *KernelTunDevice) ReadObserver() *HostKernelReadObserver {
	if d == nil {
		return nil
	}
	return d.readObs
}

func (d *KernelTunDevice) readLocked(ctx context.Context, buf []byte) (int, error) {
	if d.readObs == nil {
		return d.read(ctx, buf)
	}
	readStart := time.Now()
	n, err := d.read(ctx, buf)
	d.readObs.recordRead(time.Since(readStart).Nanoseconds(), n)
	return n, err
}

func (d *KernelTunDevice) readBatchLocked(ctx context.Context, bufs [][]byte, maxN int) (int, error) {
	if d.readObs == nil {
		return d.readBatch.ReadBatch(ctx, bufs, maxN)
	}
	readStart := time.Now()
	got, err := d.readBatch.ReadBatch(ctx, bufs, maxN)
	if got > 0 {
		d.readObs.recordRead(time.Since(readStart).Nanoseconds(), got)
	}
	return got, err
}

// ReadPacket implements pump.TunnelDevice — delegates to ReadEgressBatch (batch-only prod path).
func (d *KernelTunDevice) ReadPacket(ctx context.Context, buf []byte) (int, error) {
	if d == nil || d.read == nil {
		return 0, io.EOF
	}
	slot := []cippump.EgressSlot{{Buf: buf}}
	got, err := d.ReadEgressBatch(ctx, slot, 1)
	if err != nil {
		return 0, err
	}
	if got <= 0 {
		if ctx.Err() != nil {
			return 0, context.Cause(ctx)
		}
		return 0, nil
	}
	return slot[0].Len, nil
}

func (d *KernelTunDevice) acceptEgressBuf(buf []byte) (int, bool) {
	n, ok := prepareRelayHostEgress(buf, d.nat, d.overlayPrefixes, d.onEgress)
	if !ok {
		if d.readObs != nil {
			d.readObs.recordSkipped()
		}
		return 0, false
	}
	if d.readObs != nil {
		d.readObs.recordAccepted(n)
	}
	return n, true
}

// SetHostEgressBatch overrides syscall batch read (NativeTun ReadHostEgressBatch when VNetHdr).
func (d *KernelTunDevice) SetHostEgressBatch(batch HostEgressBatchReader) {
	if d == nil || batch == nil {
		return
	}
	d.readBatch = batch
}

// ReadEgressBatch implements pump.BatchTunnelDevice (batch-only; default single-read adapter until SetHostEgressBatch).
func (d *KernelTunDevice) ReadEgressBatch(ctx context.Context, slots []cippump.EgressSlot, maxN int) (int, error) {
	if d == nil || d.read == nil || maxN <= 0 {
		return 0, io.EOF
	}
	if maxN > len(slots) {
		maxN = len(slots)
	}
	return d.readEgressBatchHost(ctx, slots, maxN)
}

func (d *KernelTunDevice) readEgressBatchHost(ctx context.Context, slots []cippump.EgressSlot, maxN int) (int, error) {
	accepted := 0
	for accepted < maxN {
		if len(slots[accepted].Buf) == 0 {
			break
		}
		remain := maxN - accepted
		var bufsScratch [cippump.DefaultLoopInMaxBatch][]byte
		bufs := bufsScratch[:remain]
		for i := range bufs {
			bufs[i] = slots[accepted+i].Buf
		}
		readCtx := ctx
		if accepted > 0 {
			readCtx = cippump.LoopInExpiredDrainCtx()
		}
		d.readMu.Lock()
		got, err := d.readBatchLocked(readCtx, bufs, remain)
		d.readMu.Unlock()
		if err != nil {
			if accepted > 0 {
				return accepted, nil
			}
			return 0, err
		}
		if got <= 0 {
			break
		}
		for i := 0; i < got && accepted < maxN; i++ {
			n, ok := d.acceptEgressBuf(bufs[i])
			if !ok {
				continue
			}
			slots[accepted].Len = n
			accepted++
		}
	}
	return accepted, nil
}

// WritePacket implements pump.TunnelDevice (usque Device.WritePacket — error is fatal in LoopOut).
func (d *KernelTunDevice) WritePacket(pkt []byte) error {
	if d == nil || len(pkt) == 0 {
		return nil
	}
	d.nat.DNATIngressInPlace(pkt)
	n, err := d.write(pkt)
	if err != nil {
		return err
	}
	if n != len(pkt) {
		return fmt.Errorf("connect-ip kernel tun: write short %d/%d", n, len(pkt))
	}
	return nil
}

// Close is a no-op; host tun fd lifecycle is owned by sing-tun.
func (d *KernelTunDevice) Close() error {
	return nil
}

var _ cippump.TunnelDevice = (*KernelTunDevice)(nil)
var _ cippump.BatchTunnelDevice = (*KernelTunDevice)(nil)
