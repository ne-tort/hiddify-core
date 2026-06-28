package forwarder

import (
	"errors"
	"net/netip"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/checksum"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
)

func addressIsIPv6(a tcpip.Address) bool {
	return a.Len() == 16
}

func buildIPTCPPacket(
	srcAddr, dstAddr tcpip.Address,
	srcPort, dstPort uint16,
	seq, ack uint32,
	flags header.TCPFlags,
	window uint16,
	payload []byte,
	tcpOpts []byte,
) []byte {
	if addressIsIPv6(srcAddr) || addressIsIPv6(dstAddr) {
		return buildIPv6TCPPacket(srcAddr, dstAddr, srcPort, dstPort, seq, ack, flags, window, payload, tcpOpts)
	}
	return buildIPv4TCPPacket(srcAddr, dstAddr, srcPort, dstPort, seq, ack, flags, window, payload, tcpOpts)
}

func buildIPv6TCPPacket(
	srcAddr, dstAddr tcpip.Address,
	srcPort, dstPort uint16,
	seq, ack uint32,
	flags header.TCPFlags,
	window uint16,
	payload []byte,
	tcpOpts []byte,
) []byte {
	tcpHdrLen := header.TCPMinimumSize + len(tcpOpts)
	if tcpHdrLen%4 != 0 {
		pad := 4 - (tcpHdrLen % 4)
		tcpOpts = append(append([]byte(nil), tcpOpts...), bytesRepeat(header.TCPOptionNOP, pad)...)
		tcpHdrLen = header.TCPMinimumSize + len(tcpOpts)
	}
	l4Len := tcpHdrLen + len(payload)
	totalLen := header.IPv6MinimumSize + l4Len
	pkt := borrowPacket(totalLen)
	iph := header.IPv6(pkt[:header.IPv6MinimumSize])
	iph.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(l4Len),
		TransportProtocol: header.TCPProtocolNumber,
		HopLimit:          64,
		SrcAddr:           srcAddr,
		DstAddr:           dstAddr,
	})
	tcpOff := header.IPv6MinimumSize
	tc := header.TCP(pkt[tcpOff:])
	copy(tc[header.TCPMinimumSize:], tcpOpts)
	tf := header.TCPFields{
		SrcPort:       srcPort,
		DstPort:       dstPort,
		SeqNum:        seq,
		AckNum:        ack,
		DataOffset:    uint8(tcpHdrLen),
		Flags:         flags,
		WindowSize:    window,
		Checksum:      0,
		UrgentPointer: 0,
	}
	tc.Encode(&tf)
	payCsum := checksum.Checksum(payload, 0)
	xsum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, srcAddr, dstAddr, uint16(tcpHdrLen)+uint16(len(payload)))
	xsum = checksum.Combine(xsum, payCsum)
	tc.SetChecksum(^tc.CalculateChecksum(xsum))
	copy(pkt[tcpOff+tcpHdrLen:], payload)
	return pkt
}

func buildIPUDPPacket(src, dst netip.Addr, srcPort, dstPort uint16, payload []byte) ([]byte, error) {
	if dst.Is6() && !dst.Is4In6() {
		return buildIPv6UDPPacket(src, srcPort, dst, dstPort, payload)
	}
	return buildIPv4UDPPacket(src, srcPort, dst, dstPort, payload)
}

func buildIPv6UDPPacket(src netip.Addr, srcPort uint16, dst netip.Addr, dstPort uint16, payload []byte) ([]byte, error) {
	if !src.Is6() || !dst.Is6() {
		return nil, errors.New("forwarder: ipv6 udp requires ipv6 addresses")
	}
	udpLen := header.UDPMinimumSize + len(payload)
	total := header.IPv6MinimumSize + udpLen
	pkt := make([]byte, total)
	iph := header.IPv6(pkt[:header.IPv6MinimumSize])
	iph.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(udpLen),
		TransportProtocol: header.UDPProtocolNumber,
		HopLimit:          64,
		SrcAddr:           tcpipAddrFromNetip(src),
		DstAddr:           tcpipAddrFromNetip(dst),
	})
	udph := header.UDP(pkt[header.IPv6MinimumSize:])
	udph.Encode(&header.UDPFields{
		SrcPort: srcPort,
		DstPort: dstPort,
		Length:  uint16(udpLen),
	})
	xsum := header.PseudoHeaderChecksum(header.UDPProtocolNumber, iph.SourceAddress(), iph.DestinationAddress(), uint16(udpLen))
	udph.SetChecksum(^udph.CalculateChecksum(xsum))
	copy(pkt[header.IPv6MinimumSize+header.UDPMinimumSize:], payload)
	return pkt, nil
}

func tcpipAddrFromNetip(a netip.Addr) tcpip.Address {
	if a.Is4() {
		return tcpip.AddrFrom4(a.As4())
	}
	return tcpip.AddrFrom16(a.As16())
}

func ipv6L4Offset(packet []byte) (offset int, proto uint8, err error) {
	if len(packet) < header.IPv6MinimumSize {
		return 0, 0, errors.New("forwarder: ipv6 packet too short")
	}
	payloadLen := int(binaryBigEndianUint16(packet[4:6]))
	if payloadLen > 0 && len(packet) < header.IPv6MinimumSize+payloadLen {
		return 0, 0, errors.New("forwarder: truncated ipv6 packet")
	}
	nextHeader := packet[6]
	offset = header.IPv6MinimumSize
	for {
		switch nextHeader {
		case 0, 43, 60, 135, 139, 140, 253, 254:
			if len(packet) < offset+2 {
				return 0, 0, errors.New("forwarder: malformed ipv6 extension header")
			}
			hdrLen := int(packet[offset+1]+1) * 8
			if hdrLen <= 0 || len(packet) < offset+hdrLen {
				return 0, 0, errors.New("forwarder: malformed ipv6 extension header length")
			}
			nextHeader = packet[offset]
			offset += hdrLen
		case 44:
			if len(packet) < offset+8 {
				return 0, 0, errors.New("forwarder: malformed ipv6 fragment header")
			}
			nextHeader = packet[offset]
			offset += 8
		default:
			return offset, nextHeader, nil
		}
	}
}

func trimIPv6Packet(pkt []byte) []byte {
	if len(pkt) < header.IPv6MinimumSize {
		return pkt
	}
	payloadLen := int(binaryBigEndianUint16(pkt[4:6]))
	end := header.IPv6MinimumSize + payloadLen
	if payloadLen > 0 && end <= len(pkt) {
		return pkt[:end]
	}
	return pkt
}

func binaryBigEndianUint16(b []byte) uint16 {
	return uint16(b[0])<<8 | uint16(b[1])
}

func netipFromTCPip(a tcpip.Address) netip.Addr {
	if addressIsIPv6(a) {
		return netip.AddrFrom16(a.As16())
	}
	if a.Len() >= 4 {
		return netip.AddrFrom4(a.As4())
	}
	return netip.Addr{}
}

func maxSegmentPayloadForFlow(clientMSS uint16, flow tcp4Tuple) int {
	maxSeg := MaxSegmentPayload(clientMSS)
	ipHdr := header.IPv4MinimumSize
	if addressIsIPv6(flow.dstAddr) {
		ipHdr = header.IPv6MinimumSize
	}
	const tcpHdrBudget = header.TCPMinimumSize + 12
	if cap := maxIPv4Datagram - ipHdr - tcpHdrBudget; cap > 0 && maxSeg > cap {
		maxSeg = cap
	}
	return maxSeg
}
