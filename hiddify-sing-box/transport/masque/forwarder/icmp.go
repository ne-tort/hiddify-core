package forwarder

// BuildIPv4ICMPPortUnreachable builds a full IPv4 ICMP destination-unreachable/port-unreachable
// datagram embedding the original IP packet (connect-ip-go WritePacket feedback shape).
func BuildIPv4ICMPPortUnreachable(embeddedIP []byte) []byte {
	return buildIPv4ICMPPortUnreachable(embeddedIP)
}

func buildIPv4ICMPPortUnreachable(embeddedIP []byte) []byte {
	if len(embeddedIP) < 20 {
		return nil
	}
	const ipv4Min = 20
	total := ipv4Min + 8 + len(embeddedIP)
	icmpPkt := make([]byte, total)
	icmpPkt[0] = 0x45
	icmpPkt[2] = byte(total >> 8)
	icmpPkt[3] = byte(total)
	icmpPkt[8] = 64
	icmpPkt[9] = 1
	copy(icmpPkt[12:16], embeddedIP[16:20])
	copy(icmpPkt[16:20], embeddedIP[12:16])
	icmpPkt[20] = 3
	icmpPkt[21] = 3
	copy(icmpPkt[28:], embeddedIP)
	setIPv4HeaderChecksum(icmpPkt[:ipv4Min])
	return icmpPkt
}
