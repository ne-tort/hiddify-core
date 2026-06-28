package tun

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"strings"
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
		d.readObs.recordAccepted(n)
		d.nat.SNATEgressInPlace(buf[:n])
		if d.onEgress != nil {
			d.onEgress(buf[:n])
		}
		return n, nil
	}
}

// WritePacket implements pump.TunnelDevice (usque Device.WritePacket — error is fatal in LoopOut).
func (d *KernelTunDevice) WritePacket(pkt []byte) error {
	if d == nil || len(pkt) == 0 {
		return nil
	}
	out := d.nat.DNATIngress(pkt)
	n, err := d.write(out)
	if err != nil {
		if strings.TrimSpace(os.Getenv("HIDDIFY_MASQUE_CONNECT_IP_DEBUG")) == "1" {
			log.Printf("connect-ip kernel tun WritePacket err len=%d: %v", len(out), err)
		}
		return err
	}
	if n != len(out) {
		return fmt.Errorf("connect-ip kernel tun: write short %d/%d", n, len(out))
	}
	if strings.TrimSpace(os.Getenv("HIDDIFY_MASQUE_CONNECT_IP_DEBUG")) == "1" {
		log.Printf("connect-ip kernel tun WritePacket ok len=%d", len(out))
	}
	return nil
}

// Close is a no-op; host tun fd lifecycle is owned by sing-tun.
func (d *KernelTunDevice) Close() error {
	return nil
}

var _ cippump.TunnelDevice = (*KernelTunDevice)(nil)
