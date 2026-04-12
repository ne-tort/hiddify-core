package awg

import (
	"net/netip"

	awgTun "github.com/amnezia-vpn/amneziawg-go/tun"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/network"
)

type tunAdapter interface {
	network.Dialer
	awgTun.Device
	adapter.SimpleLifecycle
	Inet4Address() netip.Addr
	Inet6Address() netip.Addr
}

func inet46FromPrefixes(addresses []netip.Prefix) (v4 netip.Addr, v6 netip.Addr) {
	for _, p := range addresses {
		if p.Addr().Is4() {
			v4 = p.Addr()
			break
		}
	}
	for _, p := range addresses {
		if p.Addr().Is6() {
			v6 = p.Addr()
			break
		}
	}
	return
}
