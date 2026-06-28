package forwarder

import (
	"encoding/binary"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

const (
	ipv4HeaderLen = 20
	ipv6HeaderLen = 40
)

// BuildIPv4ICMPPortUnreachable builds a full IPv4 ICMP destination-unreachable/port-unreachable
// datagram embedding the original IP packet (connect-ip-go WritePacket feedback shape).
func BuildIPv4ICMPPortUnreachable(embeddedIP []byte) []byte {
	return buildIPv4ICMPPortUnreachable(embeddedIP)
}

// BuildIPv4ICMPAdminProhibited builds RFC 792 destination-unreachable / administratively prohibited.
func BuildIPv4ICMPAdminProhibited(embeddedIP []byte) []byte {
	return buildIPv4ICMPAdminProhibited(embeddedIP)
}

// BuildICMPv6AdminProhibited builds RFC 4443 destination-unreachable / administratively prohibited.
func BuildICMPv6AdminProhibited(embeddedIP []byte) []byte {
	return buildICMPv6AdminProhibited(embeddedIP)
}

func (f *packetForwarder) sendICMPPortUnreachable(origIP []byte) error {
	var icmpPkt []byte
	if len(origIP) > 0 && origIP[0]>>4 == 6 {
		icmpPkt = buildICMPv6PortUnreachable(origIP)
	} else {
		icmpPkt = buildIPv4ICMPPortUnreachable(origIP)
	}
	if len(icmpPkt) == 0 {
		return nil
	}
	return f.writeRaw(icmpPkt)
}

func (f *packetForwarder) sendICMPAdminProhibited(origIP []byte) error {
	icmpPkt := buildIPv4ICMPAdminProhibited(origIP)
	if len(icmpPkt) == 0 {
		return nil
	}
	return f.writeRaw(icmpPkt)
}

func (f *packetForwarder) sendICMPv6AdminProhibited(origIP []byte) error {
	icmpPkt := buildICMPv6AdminProhibited(origIP)
	if len(icmpPkt) == 0 {
		return nil
	}
	return f.writeRaw(icmpPkt)
}

func buildIPv4ICMPPortUnreachable(embeddedIP []byte) []byte {
	return buildIPv4ICMPDestUnreachable(embeddedIP, 3)
}

func buildIPv4ICMPAdminProhibited(embeddedIP []byte) []byte {
	return buildIPv4ICMPDestUnreachable(embeddedIP, 13)
}

func buildIPv4ICMPDestUnreachable(embeddedIP []byte, code uint8) []byte {
	if len(embeddedIP) < ipv4HeaderLen {
		return nil
	}
	embed := embeddedIP
	if len(embed) > ipv4HeaderLen+8 {
		embed = embed[:ipv4HeaderLen+8]
	}
	total := ipv4HeaderLen + 8 + len(embed)
	icmpPkt := make([]byte, total)
	icmpPkt[0] = 0x45
	icmpPkt[2] = byte(total >> 8)
	icmpPkt[3] = byte(total)
	icmpPkt[8] = 64
	icmpPkt[9] = 1
	copy(icmpPkt[12:16], embeddedIP[16:20])
	copy(icmpPkt[16:20], embeddedIP[12:16])
	icmpPkt[20] = 3
	icmpPkt[21] = code
	copy(icmpPkt[28:], embed)
	setIPv4HeaderChecksum(icmpPkt[:ipv4HeaderLen])
	return icmpPkt
}

func buildICMPv6AdminProhibited(embeddedIP []byte) []byte {
	return buildICMPv6DestUnreachable(embeddedIP, 1)
}

func buildICMPv6PortUnreachable(embeddedIP []byte) []byte {
	return buildICMPv6DestUnreachable(embeddedIP, 4)
}

func buildICMPv6DestUnreachable(embeddedIP []byte, code uint8) []byte {
	if len(embeddedIP) < ipv6HeaderLen {
		return nil
	}
	embed := embeddedIP
	if len(embed) > 1232 {
		embed = embed[:1232]
	}
	msg := &icmp.Message{
		Type: ipv6.ICMPTypeDestinationUnreachable,
		Code: int(code),
		Body: &icmp.DstUnreach{Data: embed},
	}
	icmpPayload, err := msg.Marshal(icmp.IPv6PseudoHeader(embeddedIP[24:40], embeddedIP[8:24]))
	if err != nil {
		return nil
	}
	out := make([]byte, ipv6HeaderLen+len(icmpPayload))
	out[0] = 6 << 4
	binary.BigEndian.PutUint16(out[4:6], uint16(len(icmpPayload)))
	out[6] = 58
	out[7] = 64
	copy(out[8:24], embeddedIP[24:40])
	copy(out[24:40], embeddedIP[8:24])
	copy(out[ipv6HeaderLen:], icmpPayload)
	return out
}

func isIPv4ICMPAdminProhibited(pkt []byte) bool {
	if len(pkt) < 28 || pkt[0]>>4 != 4 {
		return false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < ipv4HeaderLen || len(pkt) < ihl+2 || pkt[9] != 1 {
		return false
	}
	return pkt[ihl] == 3 && pkt[ihl+1] == 13
}

func isICMPv6AdminProhibited(pkt []byte) bool {
	if len(pkt) < ipv6HeaderLen+2 || pkt[0]>>4 != 6 || pkt[6] != 58 {
		return false
	}
	return pkt[ipv6HeaderLen] == 1 && pkt[ipv6HeaderLen+1] == 1
}
