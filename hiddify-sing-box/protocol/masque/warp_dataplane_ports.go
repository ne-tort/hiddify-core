package masque

import (
	"strings"

	"github.com/sagernet/sing-box/option"
)

// Cloudflare One firewall guide (MASQUE tunnel): UDP 443 primary, UDP fallbacks 500/1701/4500/4443/8443/8095.
// API often returns WG-style list (2408 first); for tunnel_protocol implying MASQUE we try 443-aligned order first.
var warpMasqueUDPFirewallPreferOrder = []uint16{
	443, 4443, 8443, 8095,
	500, 1701, 4500,
}

func tunnelProtocolSuggestsMasque(tunnelProto string) bool {
	p := strings.ToLower(strings.TrimSpace(tunnelProto))
	return p != "" && strings.Contains(p, "masque")
}

func normalizeDataplanePortStrategy(opt option.WarpMasqueProfileOptions) string {
	s := strings.ToLower(strings.TrimSpace(opt.DataplanePortStrategy))
	switch s {
	case "", option.WarpMasqueDataplanePortStrategyAuto:
		return option.WarpMasqueDataplanePortStrategyAuto
	case option.WarpMasqueDataplanePortStrategyAPIFirst:
		return option.WarpMasqueDataplanePortStrategyAPIFirst
	default:
		return option.WarpMasqueDataplanePortStrategyAuto
	}
}

func dedupeAppendPorts(preferred []uint16, extras []uint16) []uint16 {
	seen := make(map[uint16]struct{}, len(preferred)+len(extras))
	out := make([]uint16, 0, len(preferred)+len(extras))
	add := func(port uint16) {
		if port == 0 {
			return
		}
		if _, ok := seen[port]; ok {
			return
		}
		seen[port] = struct{}{}
		out = append(out, port)
	}
	for _, p := range preferred {
		add(p)
	}
	for _, p := range extras {
		add(p)
	}
	return out
}

func buildWarpMasqueDataplanePorts(tunnelProto string, apiPorts []uint16, strategy string) []uint16 {
	if strategy == option.WarpMasqueDataplanePortStrategyAPIFirst {
		return dedupeAppendPorts(apiPorts, nil)
	}
	if tunnelProtocolSuggestsMasque(tunnelProto) {
		// 443 (doc MASQUE) first, then device-profile ports (often 2408… on the same POP as QUIC),
		// then firewall fallbacks. Appending API before the full firewall list avoids spending the
		// whole startup deadline on 4443/8443/… while 2408 from the profile is still untried.
		merged := make([]uint16, 0, 1+len(apiPorts)+len(warpMasqueUDPFirewallPreferOrder))
		merged = append(merged, 443)
		merged = append(merged, apiPorts...)
		merged = append(merged, warpMasqueUDPFirewallPreferOrder...)
		return dedupeAppendPorts(merged, nil)
	}
	return dedupeAppendPorts(apiPorts, nil)
}

func capDataplanePorts(ports []uint16, max int) []uint16 {
	if max <= 0 || len(ports) <= max {
		return ports
	}
	return ports[:max]
}
