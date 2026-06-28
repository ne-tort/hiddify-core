package connectip

import (
	cipnet "github.com/sagernet/sing-box/transport/masque/connectip/netstack"
	cippump "github.com/sagernet/sing-box/transport/masque/connectip/pump"
)

// releaseOutboundPayload returns headroom-backed egress slices to pump or netstack pools (PERF-1c).
func releaseOutboundPayload(b []byte) {
	if cippump.TryReturnOutboundPayload(b) {
		return
	}
	cipnet.ReturnOutboundBuf(b)
}
