package tun

import (
	"context"
	"net/netip"

	"github.com/sagernet/sing-tun"
)

// L3OverlayNativeWire is ARCH-2 connect_ip L3 (WritePacket/ReadPacket) wired from a masque outbound.
type L3OverlayNativeWire struct {
	Prefixes         []netip.Prefix
	Send             func([]byte) error
	SendErr          func(error)
	StartIngress     func(context.Context) error
	BindStackIngress func(func([]byte) error)
	Stop             func()
}

// L3OverlayNativeOutbound wires native connect_ip L3 (required when l3_overlay_outbound is set).
type L3OverlayNativeOutbound interface {
	WireConnectIPNativeL3(
		ctx context.Context,
		tunIf tun.Tun,
		routePrefixes []netip.Prefix,
		tunHost netip.Addr,
		wireLocal netip.Addr,
	) (wire *L3OverlayNativeWire, ok bool, err error)
}
