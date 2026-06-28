package forwarder

import (
	"context"
	"log"
	"net/netip"
	"os"
	"strings"

	"github.com/sagernet/gvisor/pkg/tcpip/checksum"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
)

func (f *packetForwarder) handleIPv6ReadPacket(ctx context.Context, pkt []byte) {
	pkt = trimIPv6Packet(pkt)
	if len(pkt) < header.IPv6MinimumSize || pkt[0]>>4 != 6 {
		return
	}
	dst, ok := netip.AddrFromSlice(pkt[24:40])
	if !ok {
		return
	}
	if err := allowDestIP(dst, f.o.AllowPrivateTargets); err != nil {
		_ = f.sendICMPv6AdminProhibited(pkt)
		return
	}
	l4Off, proto, err := ipv6L4Offset(pkt)
	if err != nil {
		return
	}
	switch proto {
	case uint8(header.UDPProtocolNumber):
		f.handleUDPPacketAt(ctx, pkt, l4Off)
	case uint8(header.TCPProtocolNumber):
		f.handleIPv6TCPPacket(ctx, pkt, l4Off)
	}
}

func (f *packetForwarder) handleIPv6TCPPacket(ctx context.Context, pkt []byte, l4Off int) {
	if l4Off+header.TCPMinimumSize > len(pkt) {
		return
	}
	iph := header.IPv6(pkt)
	tc := header.TCP(pkt[l4Off:])
	doff := int(pkt[l4Off+12]>>4) * 4
	if doff < header.TCPMinimumSize || l4Off+doff > len(pkt) {
		if strings.TrimSpace(os.Getenv("HIDDIFY_MASQUE_CONNECT_IP_DEBUG")) == "1" {
			log.Printf("masque connect_ip forwarder: drop invalid ipv6 tcp header doff=%d l4Off=%d len=%d", doff, l4Off, len(pkt))
		}
		return
	}
	tcpLen := uint16(len(pkt) - l4Off)
	payloadLen := tcpLen - uint16(doff)
	var payCsum uint16
	if payloadLen > 0 {
		payCsum = checksum.Checksum(pkt[l4Off+doff:], 0)
	}
	srcAddr := iph.SourceAddress()
	dstAddr := iph.DestinationAddress()
	if csum := tc.Checksum(); csum != 0 && !tc.IsChecksumValid(srcAddr, dstAddr, payCsum, payloadLen) {
		if strings.TrimSpace(os.Getenv("HIDDIFY_MASQUE_CONNECT_IP_DEBUG")) == "1" {
			log.Printf("masque connect_ip forwarder: drop bad ipv6 tcp checksum csum=0x%04x", csum)
		}
		return
	}
	flow := tcp4Tuple{
		srcAddr: srcAddr,
		dstAddr: dstAddr,
		srcPort: tc.SourcePort(),
		dstPort: tc.DestinationPort(),
	}
	flags := tc.Flags()
	if flags&(header.TCPFlagSyn|header.TCPFlagAck) == header.TCPFlagSyn {
		f.handleSyn(ctx, pkt, tc, flow)
		return
	}
	if flags&header.TCPFlagRst != 0 {
		f.dropFlow(flow)
		return
	}
	s := f.getSession(flow)
	if s == nil {
		return
	}
	s.handleSegment(ctx, pkt, tc, l4Off, doff)
}

func ipPacketMinSize(pkt []byte) int {
	if len(pkt) == 0 {
		return header.IPv4MinimumSize
	}
	if pkt[0]>>4 == 6 {
		return header.IPv6MinimumSize
	}
	return header.IPv4MinimumSize
}
