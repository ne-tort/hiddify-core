package masque

import (
	"encoding/binary"
	"net"
	"net/netip"
)

// parseICMPPortUnreachablePeer extracts the unreachable UDP peer from a full IPv4 ICMP
// destination-unreachable/port-unreachable packet (connect-ip-go WritePacket feedback).
func parseICMPPortUnreachablePeer(icmpFullPacket []byte) (peer netip.Addr, port uint16, ok bool) {
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

func (c *connectIPUDPPacketConn) notifyICMPPortUnreachable(peer netip.Addr, port uint16) {
	if !peer.IsValid() || port == 0 {
		return
	}
	err := newUDPPortUnreachableError(&net.UDPAddr{IP: peer.AsSlice(), Port: int(port)})
	select {
	case c.icmpNotify <- err:
	default:
		select {
		case <-c.icmpNotify:
		default:
		}
		c.icmpNotify <- err
	}
	select {
	case c.icmpWake <- struct{}{}:
	default:
	}
}

// buildIPv4ICMPPortUnreachable builds a full IPv4 ICMP destination-unreachable/port-unreachable
// datagram embedding the original IP packet (connect-ip-go WritePacket feedback shape).
func buildIPv4ICMPPortUnreachable(embeddedIP []byte) []byte {
	if len(embeddedIP) < 20 {
		return nil
	}
	// Outer IP: reply to the original source (peer) from the original destination (target).
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

func (c *connectIPUDPPacketConn) takeICMPPortUnreachable() error {
	select {
	case err := <-c.icmpNotify:
		return err
	default:
		return nil
	}
}
