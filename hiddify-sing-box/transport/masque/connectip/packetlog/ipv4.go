package packetlog

import (
	"fmt"

	"github.com/sagernet/gvisor/pkg/tcpip/header"
)

// IPv4Summary formats src/dst, IP proto, and TCP/UDP ports for debug logs.
func IPv4Summary(pkt []byte) string {
	if len(pkt) < header.IPv4MinimumSize || pkt[0]>>4 != 4 {
		return fmt.Sprintf("len=%d non-ipv4", len(pkt))
	}
	ip := header.IPv4(pkt)
	if !ip.IsValid(len(pkt)) {
		return fmt.Sprintf("len=%d invalid-ipv4", len(pkt))
	}
	src := ip.SourceAddress()
	dst := ip.DestinationAddress()
	proto := ip.TransportProtocol()
	ihl := int(ip.HeaderLength())
	base := fmt.Sprintf("%s -> %s proto=%d len=%d", src, dst, proto, len(pkt))
	if ihl >= len(pkt) {
		return base
	}
	switch proto {
	case header.TCPProtocolNumber:
		if ihl+header.TCPMinimumSize > len(pkt) {
			return base + " tcp=truncated"
		}
		tcp := header.TCP(pkt[ihl:])
		flags := tcp.Flags()
		return fmt.Sprintf("%s tcp %d:%d flags=0x%02x seq=%d ack=%d payload=%d",
			base, tcp.SourcePort(), tcp.DestinationPort(), uint8(flags),
			tcp.SequenceNumber(), tcp.AckNumber(), len(pkt)-ihl-int(tcp.DataOffset()))
	case header.UDPProtocolNumber:
		if ihl+header.UDPMinimumSize > len(pkt) {
			return base + " udp=truncated"
		}
		udp := header.UDP(pkt[ihl:])
		return fmt.Sprintf("%s udp %d:%d payload=%d",
			base, udp.SourcePort(), udp.DestinationPort(), len(pkt)-ihl-header.UDPMinimumSize)
	default:
		return base
	}
}
