package tun

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"sync"
	"time"

	cippump "github.com/sagernet/sing-box/transport/masque/connectip/pump"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
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
	return &KernelTunDevice{
		read:            read,
		write:           write,
		nat:             nat,
		overlayPrefixes: append([]netip.Prefix(nil), overlayPrefixes...),
		onEgress:        onEgress,
	}
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

// ReadPacket implements pump.TunnelDevice (usque Device.ReadPacket).
func (d *KernelTunDevice) ReadPacket(ctx context.Context, buf []byte) (int, error) {
	if d == nil || d.read == nil {
		return 0, io.EOF
	}
	tunHost := d.nat.TunHost
	for {
		d.readMu.Lock()
		readStart := time.Now()
		n, err := d.read(ctx, buf)
		readElapsed := time.Since(readStart)
		d.readMu.Unlock()
		d.readObs.recordRead(readElapsed.Nanoseconds(), n)
		if err != nil {
			return 0, err
		}
		if n <= 0 {
			if ctx.Err() != nil {
				return 0, context.Cause(ctx)
			}
			return 0, nil
		}
		if !shouldRelayHostEgress(buf[:n], d.overlayPrefixes, tunHost) {
			d.readObs.recordSkipped()
			continue
		}
		n = normalizeIPv4EgressLen(buf, n)
		d.readObs.recordAccepted(n)
		d.nat.SNATEgressInPlace(buf[:n])
		fixIPv4TransportChecksum(buf[:n])
		if d.onEgress != nil {
			d.onEgress(buf[:n])
		}
		return n, nil
	}
}

func (d *KernelTunDevice) readOneAccepted(ctx context.Context, buf []byte) (int, error) {
	tunHost := d.nat.TunHost
	for {
		d.readMu.Lock()
		n, err := d.read(ctx, buf)
		d.readMu.Unlock()
		if err != nil {
			return 0, err
		}
		if n <= 0 {
			if ctx.Err() != nil {
				return 0, context.Cause(ctx)
			}
			return 0, nil
		}
		if len(buf) >= 1 && buf[0]>>4 != 4 {
			d.readObs.recordSkipped()
			continue
		}
		if !shouldRelayHostEgress(buf[:n], d.overlayPrefixes, tunHost) {
			d.readObs.recordSkipped()
			continue
		}
		n = normalizeIPv4EgressLen(buf, n)
		d.readObs.recordAccepted(n)
		d.nat.SNATEgressInPlace(buf[:n])
		fixIPv4TransportChecksum(buf[:n])
		if d.onEgress != nil {
			d.onEgress(buf[:n])
		}
		return n, nil
	}
}

// normalizeIPv4EgressLen trims trailing buffer slack so TCP checksum matches forwarder trim (IP total length).
func normalizeIPv4EgressLen(buf []byte, n int) int {
	if n <= 0 {
		return n
	}
	wire := ipv4WireLen(buf[:n])
	if wire > 0 && wire < n {
		return wire
	}
	return n
}

// SetHostEgressBatch overrides syscall batch read (NativeTun ReadHostEgressBatch when VNetHdr).
func (d *KernelTunDevice) SetHostEgressBatch(batch HostEgressBatchReader) {
	if d == nil || batch == nil {
		return
	}
	d.readBatch = batch
}

// ReadEgressBatch implements pump.BatchTunnelDevice — batch tun read when wired, else N× single read.
func (d *KernelTunDevice) ReadEgressBatch(ctx context.Context, slots []cippump.EgressSlot, maxN int) (int, error) {
	if d == nil || d.read == nil || maxN <= 0 {
		return 0, io.EOF
	}
	if maxN > len(slots) {
		maxN = len(slots)
	}
	if d.readBatch != nil {
		return d.readEgressBatchHost(ctx, slots, maxN)
	}

	accepted := 0
	for accepted < maxN {
		if len(slots[accepted].Buf) == 0 {
			break
		}
		readCtx := ctx
		if accepted > 0 {
			readCtx = cippump.LoopInExpiredDrainCtx()
		}
		readStart := time.Now()
		n, err := d.readOneAccepted(readCtx, slots[accepted].Buf)
		d.readObs.recordRead(time.Since(readStart).Nanoseconds(), n)
		if err != nil {
			if accepted > 0 {
				return accepted, nil
			}
			return 0, err
		}
		if n <= 0 {
			break
		}
		slots[accepted].Len = n
		accepted++
	}
	return accepted, nil
}

func (d *KernelTunDevice) readEgressBatchHost(ctx context.Context, slots []cippump.EgressSlot, maxN int) (int, error) {
	tunHost := d.nat.TunHost
	accepted := 0
	for accepted < maxN {
		if len(slots[accepted].Buf) == 0 {
			break
		}
		remain := maxN - accepted
		bufs := make([][]byte, remain)
		for i := range bufs {
			bufs[i] = slots[accepted+i].Buf
		}
		readCtx := ctx
		if accepted > 0 {
			readCtx = cippump.LoopInExpiredDrainCtx()
		}
		readStart := time.Now()
		d.readMu.Lock()
		got, err := d.readBatch.ReadBatch(readCtx, bufs, remain)
		d.readMu.Unlock()
		if got > 0 {
			d.readObs.recordRead(time.Since(readStart).Nanoseconds(), got)
		}
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
			n := ipv4WireLen(bufs[i])
			if n <= 0 {
				d.readObs.recordSkipped()
				continue
			}
			if !shouldRelayHostEgress(bufs[i][:n], d.overlayPrefixes, tunHost) {
				d.readObs.recordSkipped()
				continue
			}
			n = normalizeIPv4EgressLen(bufs[i], n)
			slots[accepted].Len = n
			d.readObs.recordAccepted(n)
			d.nat.SNATEgressInPlace(bufs[i][:n])
			fixIPv4TransportChecksum(bufs[i][:n])
			if d.onEgress != nil {
				d.onEgress(bufs[i][:n])
			}
			accepted++
		}
	}
	return accepted, nil
}

func ipv4WireLen(pkt []byte) int {
	if len(pkt) < header.IPv4MinimumSize || pkt[0]>>4 != 4 {
		return 0
	}
	total := int(pkt[2])<<8 | int(pkt[3])
	if total < header.IPv4MinimumSize || total > len(pkt) {
		return len(pkt)
	}
	return total
}

// WritePacket implements pump.TunnelDevice (usque Device.WritePacket — error is fatal in LoopOut).
func (d *KernelTunDevice) WritePacket(pkt []byte) error {
	if d == nil || len(pkt) == 0 {
		return nil
	}
	out := d.nat.DNATIngress(pkt)
	n, err := d.write(out)
	if err != nil {
		return err
	}
	if n != len(out) {
		return fmt.Errorf("connect-ip kernel tun: write short %d/%d", n, len(out))
	}
	return nil
}

// Close is a no-op; host tun fd lifecycle is owned by sing-tun.
func (d *KernelTunDevice) Close() error {
	return nil
}

var _ cippump.TunnelDevice = (*KernelTunDevice)(nil)
var _ cippump.BatchTunnelDevice = (*KernelTunDevice)(nil)
