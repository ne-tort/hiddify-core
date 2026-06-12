package connectip

import "encoding/binary"

// ParseICMPPTBHopMTU extracts the next-hop IP MTU from a full ICMP feedback IP packet
// (IPv4 carrying ICMP type 3 code 4, or IPv6 carrying ICMPv6 type 2).
func ParseICMPPTBHopMTU(icmpFullPacket []byte) (ipMTU int, isIPv6 bool, ok bool) {
	if len(icmpFullPacket) < 20 {
		return 0, false, false
	}
	switch icmpFullPacket[0] >> 4 {
	case 4:
		ihl := int(icmpFullPacket[0]&0x0f) * 4
		if ihl < 20 || len(icmpFullPacket) < ihl+8 {
			return 0, false, false
		}
		if icmpFullPacket[9] != 1 {
			return 0, false, false
		}
		icmpOff := ihl
		if icmpFullPacket[icmpOff] != 3 || icmpFullPacket[icmpOff+1] != 4 {
			return 0, false, false
		}
		mtu := int(binary.BigEndian.Uint16(icmpFullPacket[icmpOff+6 : icmpOff+8]))
		return mtu, false, mtu >= 576 && mtu <= 65535
	case 6:
		if len(icmpFullPacket) < 48 {
			return 0, false, false
		}
		if icmpFullPacket[6] != 58 {
			return 0, false, false
		}
		icmpOff := 40
		if len(icmpFullPacket) < icmpOff+8 {
			return 0, false, false
		}
		if icmpFullPacket[icmpOff] != 2 || icmpFullPacket[icmpOff+1] != 0 {
			return 0, false, false
		}
		mtu := int(binary.BigEndian.Uint32(icmpFullPacket[icmpOff+4 : icmpOff+8]))
		return mtu, true, mtu >= 1280 && mtu <= 65535
	default:
		return 0, false, false
	}
}
