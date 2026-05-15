package masque

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// RewriteConnectIPOutgoingPeerDst rewrites IPv4/IPv6 destination to the assigned peer address when
// router-originated replies carry an Internet dst (connect-ip-go policy would drop them).
func RewriteConnectIPOutgoingPeerDst(packet []byte, peerPrefixes []netip.Prefix) []byte {
	if len(packet) == 0 || len(peerPrefixes) == 0 {
		return packet
	}
	v := packet[0] >> 4
	if v != 4 && v != 6 {
		return packet
	}
	if connectIPPrefixContainsAddr(peerPrefixes, packetDestinationAddr(packet)) {
		return packet
	}
	peer, ok := connectIPPeerHostAddrForVersion(peerPrefixes, v)
	if !ok {
		return packet
	}
	switch v {
	case 4:
		out, ok := rewriteIPv4Destination(packet, peer)
		if !ok {
			return packet
		}
		return out
	case 6:
		out, ok := rewriteIPv6Destination(packet, peer)
		if !ok {
			return packet
		}
		return out
	default:
		return packet
	}
}

// connectIPPeerHostAddrForVersion picks the assigned peer host address matching the IP version.
// Servers often assign both 198.18.0.1/32 and fd00::1/128; using only the first prefix breaks IPv6 SNAT.
func connectIPPeerHostAddrForVersion(prefixes []netip.Prefix, version uint8) (netip.Addr, bool) {
	want6 := version == 6
	for _, p := range prefixes {
		if !p.IsValid() {
			continue
		}
		addr := p.Addr()
		if !addr.IsValid() || addr.IsUnspecified() {
			continue
		}
		if want6 {
			if addr.Is6() && !addr.Is4In6() {
				return addr, true
			}
		} else if addr.Is4() {
			return addr, true
		}
	}
	return netip.Addr{}, false
}

func connectIPPrefixContainsAddr(prefixes []netip.Prefix, addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func packetDestinationAddr(packet []byte) netip.Addr {
	if len(packet) < 1 {
		return netip.Addr{}
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return netip.Addr{}
		}
		return netip.AddrFrom4([4]byte(packet[16:20]))
	case 6:
		if len(packet) < 40 {
			return netip.Addr{}
		}
		return netip.AddrFrom16([16]byte(packet[24:40]))
	default:
		return netip.Addr{}
	}
}

func rewriteIPv4Destination(packet []byte, peer netip.Addr) ([]byte, bool) {
	if !peer.Is4() || len(packet) < 20 {
		return nil, false
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || len(packet) < ihl {
		return nil, false
	}
	out := append([]byte(nil), packet...)
	peer4 := peer.As4()
	copy(out[16:20], peer4[:])
	setIPv4HeaderChecksum(out[:ihl])
	if proto := out[9]; proto == 6 || proto == 17 {
		if len(out) >= ihl+8 {
			binary.BigEndian.PutUint16(out[ihl+16:ihl+18], 0)
			csum := transportChecksumIPv4(out[:ihl], out[ihl:], proto)
			binary.BigEndian.PutUint16(out[ihl+16:ihl+18], csum)
		}
	}
	return out, true
}

func rewriteIPv6Destination(packet []byte, peer netip.Addr) ([]byte, bool) {
	if !peer.Is6() || peer.Is4In6() || len(packet) < 40 {
		return nil, false
	}
	out := append([]byte(nil), packet...)
	peer6 := peer.As16()
	copy(out[24:40], peer6[:])
	proto := out[6]
	transportOff, err := ipv6TransportHeaderOffsetForSNAT(out)
	if err != nil || (proto != 6 && proto != 17) || len(out) < transportOff+18 {
		return out, true
	}
	binary.BigEndian.PutUint16(out[transportOff+16:transportOff+18], 0)
	csum := transportChecksumIPv6(out[:40], out[transportOff:], proto)
	binary.BigEndian.PutUint16(out[transportOff+16:transportOff+18], csum)
	return out, true
}

func ipv6TransportHeaderOffsetForSNAT(packet []byte) (int, error) {
	nextHeader := packet[6]
	offset := 40
	for {
		switch nextHeader {
		case 0, 43, 60, 135, 139, 140, 253, 254:
			if len(packet) < offset+2 {
				return 0, errors.New("invalid ipv6 extension header")
			}
			headerLen := int(packet[offset+1]+1) * 8
			if headerLen <= 0 || len(packet) < offset+headerLen {
				return 0, errors.New("invalid ipv6 extension header length")
			}
			nextHeader = packet[offset]
			offset += headerLen
		case 44:
			if len(packet) < offset+8 {
				return 0, errors.New("invalid ipv6 fragment header")
			}
			nextHeader = packet[offset]
			offset += 8
		default:
			return offset, nil
		}
	}
}

func setIPv4HeaderChecksum(header []byte) {
	if len(header) < 12 {
		return
	}
	header[10], header[11] = 0, 0
	binary.BigEndian.PutUint16(header[10:12], ^checksum16(header))
}

func checksum16(b []byte) uint16 {
	var sum uint32
	for len(b) > 1 {
		sum += uint32(binary.BigEndian.Uint16(b[:2]))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(sum)
}

func transportChecksumIPv4(header []byte, transport []byte, proto uint8) uint16 {
	pseudo := make([]byte, 0, 12+len(transport))
	pseudo = append(pseudo, header[12:16]...)
	pseudo = append(pseudo, header[16:20]...)
	pseudo = append(pseudo, 0, byte(proto))
	pseudo = append(pseudo, byte(len(transport)>>8), byte(len(transport)))
	pseudo = append(pseudo, transport...)
	return ^checksum16(pseudo)
}

func transportChecksumIPv6(header []byte, transport []byte, proto uint8) uint16 {
	pseudo := make([]byte, 0, 40+len(transport))
	pseudo = append(pseudo, header[8:24]...)
	pseudo = append(pseudo, header[24:40]...)
	pseudo = append(pseudo, 0, byte(proto))
	pseudo = append(pseudo, byte(len(transport)>>8), byte(len(transport)))
	pseudo = append(pseudo, transport...)
	return ^checksum16(pseudo)
}
