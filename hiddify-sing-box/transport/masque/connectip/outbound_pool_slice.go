package connectip

import cippump "github.com/sagernet/sing-box/transport/masque/connectip/pump"

// isOutboundPoolSlice reports pump or netstack headroom-backed egress payloads (PERF-1c).
func isOutboundPoolSlice(ip []byte) bool {
	if IsOutboundPoolSlice(ip) {
		return true
	}
	return cippump.IsOutboundPoolPayload(ip)
}
