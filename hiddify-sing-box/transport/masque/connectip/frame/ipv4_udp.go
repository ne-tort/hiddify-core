package frame

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// IPv4HeaderIndicatesFragmentation reports RFC 791 More-Fragments or a non-zero fragment offset.
func IPv4HeaderIndicatesFragmentation(b []byte) bool {
	flagsFrag := binary.BigEndian.Uint16(b[6:8])
	return flagsFrag&0x1fff != 0 || flagsFrag&0x2000 != 0
}

// ParseIPv4UDPPacketOffsets validates an IPv4/UDP frame for CONNECT-IP UDP bridge delivery.
func ParseIPv4UDPPacketOffsets(packet []byte) (payloadOff int, payloadLen int, src netip.Addr, srcPort uint16, err error) {
	if len(packet) < 28 {
		return 0, 0, netip.Addr{}, 0, errors.New("connect-ip udp bridge packet too short")
	}
	version := packet[0] >> 4
	if version != 4 {
		return 0, 0, netip.Addr{}, 0, errors.New("connect-ip udp bridge expects ipv4 packet")
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || len(packet) < ihl+8 {
		return 0, 0, netip.Addr{}, 0, errors.New("connect-ip udp bridge invalid ipv4 header length")
	}
	if IPv4HeaderIndicatesFragmentation(packet) {
		return 0, 0, netip.Addr{}, 0, errors.New("connect-ip udp bridge fragmented ipv4 is not supported for udp bridge parsing")
	}
	if packet[9] != 17 {
		return 0, 0, netip.Addr{}, 0, errors.New("connect-ip udp bridge expects udp protocol")
	}
	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLen <= 0 || totalLen > len(packet) {
		totalLen = len(packet)
	}
	udpStart := ihl
	srcAddr := netip.AddrFrom4([4]byte{
		packet[12], packet[13], packet[14], packet[15],
	})
	srcPort = binary.BigEndian.Uint16(packet[udpStart : udpStart+2])
	udpLen := int(binary.BigEndian.Uint16(packet[udpStart+4 : udpStart+6]))
	udpPayloadStart := udpStart + 8
	if udpLen < 8 || udpPayloadStart > totalLen {
		return 0, 0, netip.Addr{}, 0, errors.New("connect-ip udp bridge invalid udp length")
	}
	payloadEnd := udpStart + udpLen
	if payloadEnd > totalLen {
		payloadEnd = totalLen
	}
	if udpPayloadStart > payloadEnd {
		return udpPayloadStart, 0, srcAddr, srcPort, nil
	}
	return udpPayloadStart, payloadEnd - udpPayloadStart, srcAddr, srcPort, nil
}

// ParseIPv4UDPPacket extracts the UDP payload and source endpoint from a full IPv4/UDP frame.
func ParseIPv4UDPPacket(packet []byte) (payload []byte, src netip.Addr, srcPort uint16, err error) {
	off, ln, addr, sport, err := ParseIPv4UDPPacketOffsets(packet)
	if err != nil {
		return nil, netip.Addr{}, 0, err
	}
	return packet[off : off+ln], addr, sport, nil
}

// BuildIPv4UDPPacket builds a minimal IPv4/UDP datagram with a valid IPv4 header checksum.
func BuildIPv4UDPPacket(src netip.Addr, srcPort uint16, dst netip.Addr, dstPort uint16, payload []byte) ([]byte, error) {
	return BuildIPv4UDPPacketInplace(nil, src, srcPort, dst, dstPort, payload)
}

// BuildIPv4UDPPacketInplace builds into buffer when capacity allows; otherwise allocates.
func BuildIPv4UDPPacketInplace(buffer []byte, src netip.Addr, srcPort uint16, dst netip.Addr, dstPort uint16, payload []byte) ([]byte, error) {
	if !src.Is4() || !dst.Is4() {
		return nil, errors.New("ipv4 udp packet builder requires ipv4 addresses")
	}
	return BuildIPv4UDPPacketInplaceV4(buffer, src.As4(), srcPort, dst.As4(), dstPort, payload)
}

// BuildIPv4UDPPacketInplaceV4 is the IPv4-only variant of BuildIPv4UDPPacketInplace.
func BuildIPv4UDPPacketInplaceV4(buffer []byte, src4 [4]byte, srcPort uint16, dst4 [4]byte, dstPort uint16, payload []byte) ([]byte, error) {
	return BuildIPv4UDPPacketInplaceHeaderV4(buffer, NewIPv4UDPHeaderTemplate(src4, srcPort, dst4, dstPort), payload)
}

// NewIPv4UDPHeaderTemplate returns a reusable 28-byte IPv4+UDP header prefix for hot-path builds.
func NewIPv4UDPHeaderTemplate(src4 [4]byte, srcPort uint16, dst4 [4]byte, dstPort uint16) [28]byte {
	var header [28]byte
	header[0] = 0x45
	header[1] = 0x00
	binary.BigEndian.PutUint16(header[4:6], 0)
	binary.BigEndian.PutUint16(header[6:8], 0)
	header[8] = 64
	header[9] = 17
	copy(header[12:16], src4[:])
	copy(header[16:20], dst4[:])
	binary.BigEndian.PutUint16(header[20:22], srcPort)
	binary.BigEndian.PutUint16(header[22:24], dstPort)
	return header
}

// BuildIPv4UDPPacketInplaceHeaderV4 fills buffer using a pre-built header template and payload.
func BuildIPv4UDPPacketInplaceHeaderV4(buffer []byte, headerTemplate [28]byte, payload []byte) ([]byte, error) {
	const ipv4HeaderLen = 20
	const udpHeaderLen = 8
	totalLen := ipv4HeaderLen + udpHeaderLen + len(payload)
	packet := buffer
	if cap(packet) < totalLen {
		packet = make([]byte, totalLen)
	} else {
		packet = packet[:totalLen]
	}
	copy(packet[:udpHeaderLen+ipv4HeaderLen], headerTemplate[:])
	binary.BigEndian.PutUint16(packet[2:4], uint16(totalLen))
	// headerTemplate keeps bytes [10:12] zero so IPv4HeaderChecksum always reads zeros for the checksum field.
	binary.BigEndian.PutUint16(packet[10:12], IPv4HeaderChecksum(packet[:ipv4HeaderLen]))
	binary.BigEndian.PutUint16(packet[24:26], uint16(udpHeaderLen+len(payload)))
	binary.BigEndian.PutUint16(packet[26:28], 0)
	copy(packet[28:], payload)
	return packet, nil
}

// IPv4HeaderChecksum computes the IPv4 header checksum (RFC 791).
func IPv4HeaderChecksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(header); i += 2 {
		if i == 10 {
			continue
		}
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	for (sum >> 16) != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
