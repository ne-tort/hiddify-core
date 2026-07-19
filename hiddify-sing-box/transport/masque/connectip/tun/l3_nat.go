package tun

import (
	"encoding/binary"
	"net/netip"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/checksum"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
)

// OverlayNAT maps between sing-tun host address and CONNECT-IP wire-local (RFC 9484 assigned).
// Optional VirtTarget→WireTarget rewrites app-visible bench IPs to loopback (in-proc TUN synth).
type OverlayNAT struct {
	TunHost    netip.Addr
	WireLocal  netip.Addr
	VirtTarget netip.Addr
	WireTarget netip.Addr
}

func (n OverlayNAT) enabled() bool {
	return n.TunHost.IsValid() && n.WireLocal.IsValid() && n.TunHost != n.WireLocal
}

func (n OverlayNAT) hairpinEnabled() bool {
	return n.VirtTarget.IsValid() && n.WireTarget.IsValid() && n.VirtTarget != n.WireTarget
}

// SNATEgress rewrites IPv4 for CONNECT-IP wire: tun host → wire local; virt target → loopback hairpin.
func (n OverlayNAT) SNATEgress(pkt []byte) []byte {
	if len(pkt) < header.IPv4MinimumSize || pkt[0]>>4 != 4 {
		return pkt
	}
	out := pkt
	if n.enabled() {
		if src, ok := ipv4Source(out); ok && src == n.TunHost {
			out = rewriteIPv4Source(out, n.WireLocal)
			fixIPv4TransportChecksum(out)
		}
	}
	if n.hairpinEnabled() {
		if dst, ok := ipv4Destination(out); ok && dst == n.VirtTarget {
			out = rewriteIPv4Destination(out, n.WireTarget)
			fixIPv4TransportChecksum(out)
		}
	}
	return out
}

// SNATEgressInPlace applies SNATEgress on pkt without allocating (host-kernel LoopIn hot path).
func (n OverlayNAT) SNATEgressInPlace(pkt []byte) {
	if len(pkt) < header.IPv4MinimumSize || pkt[0]>>4 != 4 {
		return
	}
	if n.enabled() {
		if src, ok := ipv4Source(pkt); ok && src == n.TunHost {
			rewriteIPv4SourceInPlace(pkt, n.WireLocal)
			fixIPv4TransportChecksum(pkt)
		}
	}
	if n.hairpinEnabled() {
		if dst, ok := ipv4Destination(pkt); ok && dst == n.VirtTarget {
			rewriteIPv4DestinationInPlace(pkt, n.WireTarget)
			fixIPv4TransportChecksum(pkt)
		}
	}
}

// DNATIngress rewrites IPv4 for tun inject: wire local → tun host; loopback → virt target on return.
// Also inverse-NATs IPv4 headers quoted inside ICMP errors (PTB / DestUnreach / TimeExceeded) so
// host PMTUD sees TunHost, not WireLocal (P1-8 / F4-03).
func (n OverlayNAT) DNATIngress(pkt []byte) []byte {
	if len(pkt) < header.IPv4MinimumSize || pkt[0]>>4 != 4 {
		return pkt
	}
	out := pkt
	if n.hairpinEnabled() {
		if src, ok := ipv4Source(out); ok && src == n.WireTarget {
			out = rewriteIPv4Source(out, n.VirtTarget)
			fixIPv4TransportChecksum(out)
		}
	}
	if n.enabled() {
		if dst, ok := ipv4Destination(out); ok && dst == n.WireLocal {
			out = rewriteIPv4Destination(out, n.TunHost)
			fixIPv4TransportChecksum(out)
		}
	}
	n.dnatICMPQuotedIPv4InPlace(out)
	return out
}

// DNATIngressInPlace applies DNATIngress on pkt without allocating (host-kernel LoopOut hot path).
func (n OverlayNAT) DNATIngressInPlace(pkt []byte) {
	if len(pkt) < header.IPv4MinimumSize || pkt[0]>>4 != 4 {
		return
	}
	if n.hairpinEnabled() {
		if src, ok := ipv4Source(pkt); ok && src == n.WireTarget {
			rewriteIPv4SourceInPlace(pkt, n.VirtTarget)
			fixIPv4TransportChecksum(pkt)
		}
	}
	if n.enabled() {
		if dst, ok := ipv4Destination(pkt); ok && dst == n.WireLocal {
			rewriteIPv4DestinationInPlace(pkt, n.TunHost)
			fixIPv4TransportChecksum(pkt)
		}
	}
	n.dnatICMPQuotedIPv4InPlace(pkt)
}

// dnatICMPQuotedIPv4InPlace rewrites embedded IPv4 headers in ICMP error messages.
// Inverse of SNATEgress: WireLocal→TunHost (src), WireTarget→VirtTarget (dst).
func (n OverlayNAT) dnatICMPQuotedIPv4InPlace(pkt []byte) {
	if !n.enabled() && !n.hairpinEnabled() {
		return
	}
	if len(pkt) < header.IPv4MinimumSize || pkt[0]>>4 != 4 {
		return
	}
	ip := header.IPv4(pkt)
	if ip.TransportProtocol() != header.ICMPv4ProtocolNumber {
		return
	}
	ihl := int(ip.HeaderLength())
	const icmpHdrMin = 8
	if ihl+icmpHdrMin > len(pkt) {
		return
	}
	switch pkt[ihl] { // ICMPv4 type
	case 3, 11, 12: // Dest Unreachable, Time Exceeded, Param Problem
	default:
		return
	}
	quote := pkt[ihl+icmpHdrMin:]
	if len(quote) < header.IPv4MinimumSize || quote[0]>>4 != 4 {
		return
	}
	changed := false
	if n.enabled() {
		if src, ok := ipv4Source(quote); ok && src == n.WireLocal {
			rewriteIPv4SourceInPlace(quote, n.TunHost)
			changed = true
		}
	}
	if n.hairpinEnabled() {
		if dst, ok := ipv4Destination(quote); ok && dst == n.WireTarget {
			rewriteIPv4DestinationInPlace(quote, n.VirtTarget)
			changed = true
		}
	}
	if changed {
		fixICMPv4Checksum(pkt, ihl)
	}
}

func fixICMPv4Checksum(pkt []byte, ihl int) {
	if ihl < header.IPv4MinimumSize || ihl+8 > len(pkt) {
		return
	}
	body := pkt[ihl:]
	// Zero checksum field then fold.
	body[2], body[3] = 0, 0
	sum := checksum.Checksum(body, 0)
	binary.BigEndian.PutUint16(body[2:4], ^sum)
}

func fixIPv4TransportChecksum(pkt []byte) {
	if len(pkt) < header.IPv4MinimumSize {
		return
	}
	ip := header.IPv4(pkt)
	if !ip.IsValid(len(pkt)) {
		ip.SetChecksum(0)
		ip.SetChecksum(^ip.CalculateChecksum())
	}
	ihl := int(ip.HeaderLength())
	if ihl >= len(pkt) {
		return
	}
	src := ip.SourceAddress()
	dst := ip.DestinationAddress()
	switch ip.TransportProtocol() {
	case header.TCPProtocolNumber:
		if ihl+header.TCPMinimumSize > len(pkt) {
			return
		}
		tcp := header.TCP(pkt[ihl:])
		doff := int(tcp.DataOffset())
		if doff < header.TCPMinimumSize || ihl+doff > len(pkt) {
			return
		}
		tcpLen := uint16(len(pkt) - ihl)
		payloadLen := tcpLen - uint16(doff)
		var payCsum uint16
		if payloadLen > 0 {
			payCsum = checksum.Checksum(pkt[ihl+doff:], 0)
		}
		xsum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, src, dst, tcpLen)
		xsum = checksum.Combine(xsum, payCsum)
		tcp.SetChecksum(0)
		tcp.SetChecksum(^tcp.CalculateChecksum(xsum))
	case header.UDPProtocolNumber:
		if ihl+header.UDPMinimumSize > len(pkt) {
			return
		}
		udp := header.UDP(pkt[ihl:])
		udpLen := uint16(len(pkt) - ihl)
		payloadLen := udpLen - header.UDPMinimumSize
		var payCsum uint16
		if payloadLen > 0 {
			payCsum = checksum.Checksum(pkt[ihl+header.UDPMinimumSize:], 0)
		}
		xsum := header.PseudoHeaderChecksum(header.UDPProtocolNumber, src, dst, udpLen)
		xsum = checksum.Combine(xsum, payCsum)
		udp.SetChecksum(0)
		if csum := udp.CalculateChecksum(xsum); csum != 0 {
			udp.SetChecksum(^csum)
		}
	}
}

func ipv4Source(pkt []byte) (netip.Addr, bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte{pkt[12], pkt[13], pkt[14], pkt[15]}), true
}

func ipv4Destination(pkt []byte) (netip.Addr, bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte{pkt[16], pkt[17], pkt[18], pkt[19]}), true
}

func toTCPAddr(addr netip.Addr) tcpip.Address {
	if addr.Is4() {
		return tcpip.AddrFrom4(addr.As4())
	}
	return tcpip.AddrFrom16(addr.As16())
}

func rewriteIPv4Source(pkt []byte, newSrc netip.Addr) []byte {
	out := append([]byte(nil), pkt...)
	rewriteIPv4SourceInPlace(out, newSrc)
	return out
}

func rewriteIPv4Destination(pkt []byte, newDst netip.Addr) []byte {
	out := append([]byte(nil), pkt...)
	rewriteIPv4DestinationInPlace(out, newDst)
	return out
}

func rewriteIPv4SourceInPlace(pkt []byte, newSrc netip.Addr) {
	h := header.IPv4(pkt)
	h.SetSourceAddress(toTCPAddr(newSrc))
	h.SetChecksum(0)
	h.SetChecksum(^h.CalculateChecksum())
}

func rewriteIPv4DestinationInPlace(pkt []byte, newDst netip.Addr) {
	h := header.IPv4(pkt)
	h.SetDestinationAddress(toTCPAddr(newDst))
	h.SetChecksum(0)
	h.SetChecksum(^h.CalculateChecksum())
}
