//go:build with_gvisor

package pump

import (
	"context"
	"errors"
	"sync"

	"github.com/sagernet/sing-tun"
)

// TunGVisorDevice routes full IP frames between sing-tun gVisor L3 overlay and CONNECT-IP pump.
// W-IP-ARCH-2: wire L3OverlaySend from sing-tun StackOptions into Egress/Ingress hooks.
//
// Spike: experiments/router/.../replace/sing-tun/stack_gvisor_filter.go (L3OverlayPrefixes + L3OverlaySend).
type TunGVisorDevice struct {
	mu      sync.Mutex
	closed  bool
	stack   tun.Stack
	egress  func(context.Context, []byte) (int, error)
	ingress func([]byte) error
}

// TunGVisorDeviceConfig configures TUN-side TunnelDevice once L3 overlay is ported to main sing-tun.
type TunGVisorDeviceConfig struct {
	Stack tun.Stack
	// Egress reads IP frames leaving tun gVisor toward CONNECT-IP (LoopIn Device.ReadPacket).
	Egress func(context.Context, []byte) (int, error)
	// Ingress injects IP frames from CONNECT-IP into tun gVisor (LoopOut Device.WritePacket).
	Ingress func([]byte) error
}

// NewTunGVisorDevice returns a TunnelDevice; Egress/Ingress must be set before RunTunnel (ARCH-2).
func NewTunGVisorDevice(cfg TunGVisorDeviceConfig) *TunGVisorDevice {
	return &TunGVisorDevice{
		stack:   cfg.Stack,
		egress:  cfg.Egress,
		ingress: cfg.Ingress,
	}
}

func (d *TunGVisorDevice) ReadPacket(ctx context.Context, buf []byte) (int, error) {
	d.mu.Lock()
	closed := d.closed
	egress := d.egress
	d.mu.Unlock()
	if closed {
		return 0, errors.New("tun gvisor device closed")
	}
	if egress == nil {
		return 0, errors.New("tun gvisor device: Egress not wired (W-IP-ARCH-2)")
	}
	return egress(ctx, buf)
}

func (d *TunGVisorDevice) WritePacket(pkt []byte) error {
	d.mu.Lock()
	closed := d.closed
	ingress := d.ingress
	d.mu.Unlock()
	if closed {
		return errors.New("tun gvisor device closed")
	}
	if ingress == nil {
		return errors.New("tun gvisor device: Ingress not wired (W-IP-ARCH-2)")
	}
	return ingress(pkt)
}

func (d *TunGVisorDevice) ScheduleOutboundDrain() {}

func (d *TunGVisorDevice) Close() error {
	d.mu.Lock()
	d.closed = true
	d.mu.Unlock()
	return nil
}
