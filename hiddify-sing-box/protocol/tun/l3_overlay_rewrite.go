package tun

import (
	"net/netip"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/checksum"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
)

// rewriteL3OverlayEgressIPv4 sets IPv4 source to rewriteSrc (overlay identity) and fixes
// checksums. gVisor may emit 198.18.0.0/30 as source while the router ACL expects the
// overlay address listed in tun "address" (e.g. 10.0.0.2/32).
func rewriteL3OverlayEgressIPv4(packet []byte, rewriteSrc netip.Addr) {
	if !rewriteSrc.IsValid() || !rewriteSrc.Is4() {
		return
	}
	if len(packet) < header.IPv4MinimumSize || packet[0]>>4 != 4 {
		return
	}
	ipHdr := header.IPv4(packet)
	totalLen := int(ipHdr.TotalLength())
	if len(packet) < totalLen {
		return
	}
	oldSrc := netip.AddrFrom4([4]byte(ipHdr.SourceAddressSlice()))
	if oldSrc == rewriteSrc {
		return
	}
	newTCP := tcpip.AddrFrom4(rewriteSrc.As4())
	ipHdr.SetSourceAddressWithChecksumUpdate(newTCP)

	payload := ipHdr.Payload()
	switch ipHdr.TransportProtocol() {
	case header.TCPProtocolNumber:
		if len(payload) < header.TCPMinimumSize {
			return
		}
		tcpHdr := header.TCP(payload)
		tcpHdr.SetChecksum(0)
		srcA := tcpip.AddrFrom4Slice(ipHdr.SourceAddressSlice())
		dstA := tcpip.AddrFrom4Slice(ipHdr.DestinationAddressSlice())
		tcpHdr.SetChecksum(^checksum.Checksum(tcpHdr.Payload(), tcpHdr.CalculateChecksum(
			header.PseudoHeaderChecksum(header.TCPProtocolNumber, srcA, dstA, ipHdr.PayloadLength()))))
	case header.UDPProtocolNumber:
		if len(payload) < header.UDPMinimumSize {
			return
		}
		udpHdr := header.UDP(payload)
		udpHdr.SetChecksum(0)
		srcA := tcpip.AddrFrom4Slice(ipHdr.SourceAddressSlice())
		dstA := tcpip.AddrFrom4Slice(ipHdr.DestinationAddressSlice())
		udpHdr.SetChecksum(^checksum.Checksum(udpHdr.Payload(), udpHdr.CalculateChecksum(
			header.PseudoHeaderChecksum(header.UDPProtocolNumber, srcA, dstA, ipHdr.PayloadLength()))))
	}
}
