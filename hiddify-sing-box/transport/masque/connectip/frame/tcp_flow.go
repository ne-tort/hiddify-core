package frame

import "github.com/sagernet/gvisor/pkg/tcpip/header"

// TCP4Flow identifies an IPv4 TCP 4-tuple for egress/forwarder coalesce keys.
type TCP4Flow struct {
	Src, Dst       [4]byte
	SrcPort, DstPort uint16
}

// TCP4FlowFromIPv4 extracts the TCP 4-tuple from an IPv4 packet.
func TCP4FlowFromIPv4(pkt []byte) (TCP4Flow, bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 || pkt[9] != uint8(header.TCPProtocolNumber) {
		return TCP4Flow{}, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl+12 > len(pkt) {
		return TCP4Flow{}, false
	}
	return TCP4Flow{
		Src:     [4]byte{pkt[12], pkt[13], pkt[14], pkt[15]},
		Dst:     [4]byte{pkt[16], pkt[17], pkt[18], pkt[19]},
		SrcPort: uint16(pkt[ihl])<<8 | uint16(pkt[ihl+1]),
		DstPort: uint16(pkt[ihl+2])<<8 | uint16(pkt[ihl+3]),
	}, true
}
