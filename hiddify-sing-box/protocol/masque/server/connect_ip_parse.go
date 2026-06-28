package server

import (
	"net/netip"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

// ParseIPDestinationAndPayload extracts destination and UDP payload bounds from a raw IP packet.
func ParseIPDestinationAndPayload(packet []byte) (M.Socksaddr, int, int, error) {
	if len(packet) < 1 {
		return M.Socksaddr{}, 0, 0, E.New("invalid empty ip packet")
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return M.Socksaddr{}, 0, 0, E.New("invalid ipv4 packet")
		}
		ihl := int(packet[0]&0x0f) * 4
		if ihl < 20 || len(packet) < ihl {
			return M.Socksaddr{}, 0, 0, E.New("invalid ipv4 header length")
		}
		destination := M.Socksaddr{Addr: netip.AddrFrom4([4]byte(packet[16:20]))}
		protocol := packet[9]
		if (packet[9] == 6 || packet[9] == 17) && len(packet) >= ihl+4 {
			destination.Port = uint16(packet[ihl+2])<<8 | uint16(packet[ihl+3])
		}
		payloadStart, payloadEnd := 0, len(packet)
		if protocol == 17 && len(packet) >= ihl+8 {
			totalLen := int(uint16(packet[2])<<8 | uint16(packet[3]))
			if totalLen <= 0 || totalLen > len(packet) {
				totalLen = len(packet)
			}
			udpLen := int(uint16(packet[ihl+4])<<8 | uint16(packet[ihl+5]))
			payloadStart = ihl + 8
			payloadEnd = totalLen
			if udpLen >= 8 {
				payloadEnd = intMin(payloadEnd, ihl+udpLen)
			}
			if payloadStart > payloadEnd || payloadEnd > len(packet) {
				return M.Socksaddr{}, 0, 0, E.New("invalid ipv4 udp payload")
			}
		}
		return destination, payloadStart, payloadEnd, nil
	case 6:
		if len(packet) < 40 {
			return M.Socksaddr{}, 0, 0, E.New("invalid ipv6 packet")
		}
		destination := M.Socksaddr{Addr: netip.AddrFrom16([16]byte(packet[24:40]))}
		nextHeader, transportOffset, err := ipv6TransportHeaderOffset(packet)
		if err != nil {
			return M.Socksaddr{}, 0, 0, err
		}
		if (nextHeader == 6 || nextHeader == 17) && len(packet) >= transportOffset+4 {
			destination.Port = uint16(packet[transportOffset+2])<<8 | uint16(packet[transportOffset+3])
		}
		payloadStart, payloadEnd := 0, len(packet)
		if nextHeader == 17 && len(packet) >= transportOffset+8 {
			payloadStart = transportOffset + 8
			totalLen := len(packet)
			ipPayloadLen := int(uint16(packet[4])<<8 | uint16(packet[5]))
			if ipPayloadLen > 0 {
				totalLen = intMin(totalLen, 40+ipPayloadLen)
			}
			payloadEnd = totalLen
			udpLen := int(uint16(packet[transportOffset+4])<<8 | uint16(packet[transportOffset+5]))
			if udpLen >= 8 {
				payloadEnd = intMin(payloadEnd, transportOffset+udpLen)
			}
			if payloadStart > payloadEnd || payloadEnd > len(packet) {
				return M.Socksaddr{}, 0, 0, E.New("invalid ipv6 udp payload")
			}
		}
		return destination, payloadStart, payloadEnd, nil
	default:
		return M.Socksaddr{}, 0, 0, E.New("unsupported ip packet version")
	}
}

func ipv6TransportHeaderOffset(packet []byte) (uint8, int, error) {
	nextHeader := packet[6]
	offset := 40
	for {
		switch nextHeader {
		case 0, 43, 60, 135, 139, 140, 253, 254:
			if len(packet) < offset+2 {
				return 0, 0, E.New("invalid ipv6 extension header")
			}
			headerLen := int(packet[offset+1]+1) * 8
			if headerLen <= 0 || len(packet) < offset+headerLen {
				return 0, 0, E.New("invalid ipv6 extension header length")
			}
			nextHeader = packet[offset]
			offset += headerLen
		case 44:
			if len(packet) < offset+8 {
				return 0, 0, E.New("invalid ipv6 fragment header")
			}
			nextHeader = packet[offset]
			offset += 8
		default:
			return nextHeader, offset, nil
		}
	}
}

func intMin(a, b int) int {
	if a < b {
		return a
	}
	return b
}
