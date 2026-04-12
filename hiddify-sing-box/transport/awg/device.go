package awg

import (
	"context"
	"net/netip"
	"time"

	"github.com/sagernet/sing-box/log"
	singtun "github.com/sagernet/sing-tun"
)

// tunPickOptions groups inputs for choosing the TUN implementation (mirrors wireguard.NewDevice branching).
// When system is false, we use sing-tun gvisor stack (newAwgStackDevice), same model as WireGuard newStackDevice.
//
// When system is true and sing-tun is built with gvisor, WireGuard uses newSystemStackDevice (kernel TUN + gvisor
// overlay via wireguard device.InputPacket). Upstream amneziawg-go does not expose InputPacket, so AWG cannot
// implement that hybrid; we keep kernel-only newSystemTun for both branches (see transport/awg/doc.go).
type tunPickOptions struct {
	Context        context.Context
	Logger         log.ContextLogger
	Handler        singtun.Handler
	UDPTimeout     time.Duration
	System         bool
	Address        []netip.Prefix
	AllowedPrefix  []netip.Prefix
	ExcludedPrefix []netip.Prefix
	MTU            uint32
	Name           string
}

func newTunForEndpoint(opt tunPickOptions) (tunAdapter, error) {
	if !opt.System {
		return newAwgStackDevice(opt)
	}
	if !singtun.WithGVisor {
		return newSystemTun(opt.Context, opt.Address, opt.AllowedPrefix, opt.ExcludedPrefix, opt.MTU, opt.Logger, opt.Name)
	}
	// No amneziawg equivalent of wireguard device.InputPacket for systemStackDevice; use kernel TUN only.
	return newSystemTun(opt.Context, opt.Address, opt.AllowedPrefix, opt.ExcludedPrefix, opt.MTU, opt.Logger, opt.Name)
}
