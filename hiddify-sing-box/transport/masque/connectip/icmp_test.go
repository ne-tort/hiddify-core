package connectip

import (
	"net/netip"
	"testing"
)

func TestParseICMPPortUnreachablePeerIPv4(t *testing.T) {
	orig := buildTestIPv4UDPPacket(
		netip.MustParseAddr("198.18.0.2"),
		53000,
		netip.MustParseAddr("10.200.0.2"),
		5601,
		[]byte("dns"),
	)
	icmpPkt := make([]byte, 20+8+len(orig))
	icmpPkt[0] = 0x45
	icmpPkt[9] = 1
	icmpPkt[20] = 3
	icmpPkt[21] = 3
	copy(icmpPkt[28:], orig)
	peer, port, ok := ParseICMPPortUnreachablePeer(icmpPkt)
	if !ok || peer != netip.MustParseAddr("10.200.0.2") || port != 5601 {
		t.Fatalf("parse: peer=%v port=%d ok=%v", peer, port, ok)
	}
}

func buildTestIPv4UDPPacket(src netip.Addr, srcPort uint16, dst netip.Addr, dstPort uint16, payload []byte) []byte {
	const ipHdr = 20
	const udpHdr = 8
	pkt := make([]byte, ipHdr+udpHdr+len(payload))
	pkt[0] = 0x45
	pkt[9] = 17
	s4 := src.As4()
	d4 := dst.As4()
	copy(pkt[12:16], s4[:])
	copy(pkt[16:20], d4[:])
	pkt[ipHdr+0] = byte(srcPort >> 8)
	pkt[ipHdr+1] = byte(srcPort)
	pkt[ipHdr+2] = byte(dstPort >> 8)
	pkt[ipHdr+3] = byte(dstPort)
	copy(pkt[ipHdr+udpHdr:], payload)
	return pkt
}
