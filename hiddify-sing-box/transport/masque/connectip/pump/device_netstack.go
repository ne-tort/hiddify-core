package pump

import (
	cipnet "github.com/sagernet/sing-box/transport/masque/connectip/netstack"
)

// NetstackDevice adapts connectip/netstack for RunTunnel (non-TUN native path).
func NetstackDevice(ns *cipnet.Netstack) TunnelDevice {
	return cipnet.NewDeviceAdapter(ns)
}
