package tun

import (
	"net/netip"

	"github.com/sagernet/gvisor/pkg/tcpip/header"
)

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

func shouldRelayHostEgress(pkt []byte, prefixes []netip.Prefix, tunHost netip.Addr) bool {
	if len(pkt) < header.IPv4MinimumSize || pkt[0]>>4 != 4 {
		return false
	}
	dst, ok := ipv4Destination(pkt)
	if !ok || !dst.IsValid() || dst == tunHost {
		return false
	}
	if len(prefixes) == 0 {
		return dst.IsGlobalUnicast()
	}
	for _, p := range prefixes {
		if p.IsValid() && p.Contains(dst) {
			return true
		}
	}
	return false
}

// prepareRelayHostEgress validates wire IPv4, applies overlay prefix filter, SNAT, and transport checksum fix.
func prepareRelayHostEgress(buf []byte, nat OverlayNAT, prefixes []netip.Prefix, onEgress func([]byte)) (int, bool) {
	n := ipv4WireLen(buf)
	if n <= 0 {
		return 0, false
	}
	if !shouldRelayHostEgress(buf[:n], prefixes, nat.TunHost) {
		return 0, false
	}
	n = normalizeIPv4EgressLen(buf, n)
	nat.SNATEgressInPlace(buf[:n])
	fixIPv4TransportChecksum(buf[:n])
	if onEgress != nil {
		onEgress(buf[:n])
	}
	return n, true
}
