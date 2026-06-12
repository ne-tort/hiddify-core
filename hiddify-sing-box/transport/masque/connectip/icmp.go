package connectip

import (
	"encoding/binary"
	"net/netip"
)

// ParseICMPPortUnreachablePeer extracts the unreachable UDP peer from a full IPv4 ICMP
// destination-unreachable/port-unreachable packet (connect-ip-go WritePacket feedback).
func ParseICMPPortUnreachablePeer(icmpFullPacket []byte) (peer netip.Addr, port uint16, ok bool) {
	if len(icmpFullPacket) < 28 {
		return netip.Addr{}, 0, false
	}
	if icmpFullPacket[0]>>4 != 4 {
		return netip.Addr{}, 0, false
	}
	ihl := int(icmpFullPacket[0]&0x0f) * 4
	if ihl < 20 || len(icmpFullPacket) < ihl+8 || icmpFullPacket[9] != 1 {
		return netip.Addr{}, 0, false
	}
	icmpOff := ihl
	if icmpFullPacket[icmpOff] != 3 || icmpFullPacket[icmpOff+1] != 3 {
		return netip.Addr{}, 0, false
	}
	emb := icmpOff + 8
	if len(icmpFullPacket) < emb+28 {
		return netip.Addr{}, 0, false
	}
	embIHl := int(icmpFullPacket[emb]&0x0f) * 4
	if embIHl < 20 || len(icmpFullPacket) < emb+embIHl+4 {
		return netip.Addr{}, 0, false
	}
	if icmpFullPacket[emb+9] != 17 {
		return netip.Addr{}, 0, false
	}
	peer = netip.AddrFrom4([4]byte{
		icmpFullPacket[emb+16], icmpFullPacket[emb+17],
		icmpFullPacket[emb+18], icmpFullPacket[emb+19],
	})
	port = binary.BigEndian.Uint16(icmpFullPacket[emb+embIHl+2 : emb+embIHl+4])
	return peer, port, true
}
