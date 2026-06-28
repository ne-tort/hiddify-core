package forwarder

import (
	"context"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/checksum"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
)

func TestBuildIPv6TCPPacketChecksumValid(t *testing.T) {
	t.Parallel()
	src := tcpip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})
	dst := tcpip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	pkt := buildIPv6TCPPacket(src, dst, 443, 52001, 1, 2, header.TCPFlagSyn|header.TCPFlagAck, 65535, nil, nil)
	l4Off := header.IPv6MinimumSize
	tc := header.TCP(pkt[l4Off:])
	doff := int(pkt[l4Off+12]>>4) * 4
	tcpLen := uint16(len(pkt) - l4Off)
	payloadLen := tcpLen - uint16(doff)
	payCsum := checksum.Checksum(pkt[l4Off+doff:], 0)
	if !tc.IsChecksumValid(src, dst, payCsum, payloadLen) {
		t.Fatal("invalid ipv6 tcp checksum")
	}
}

func TestBuildIPv6UDPPacket(t *testing.T) {
	t.Parallel()
	src := netip.MustParseAddr("2001:db8::2")
	dst := netip.MustParseAddr("2001:db8::1")
	pkt, err := buildIPv6UDPPacket(src, 53000, dst, 53, []byte("ping"))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(pkt) != header.IPv6MinimumSize+header.UDPMinimumSize+4 {
		t.Fatalf("len=%d", len(pkt))
	}
	if pkt[0]>>4 != 6 || pkt[6] != uint8(header.UDPProtocolNumber) {
		t.Fatalf("bad ipv6/udp header")
	}
}

func TestIPv6L4OffsetSkipsExtensionHeader(t *testing.T) {
	t.Parallel()
	pkt := make([]byte, header.IPv6MinimumSize+8+header.TCPMinimumSize)
	pkt[0] = 6 << 4
	pkt[6] = 0 // hop-by-hop
	pkt[7] = 64
	copy(pkt[8:24], netip.MustParseAddr("2001:db8::2").AsSlice())
	copy(pkt[24:40], netip.MustParseAddr("2001:db8::1").AsSlice())
	binary.BigEndian.PutUint16(pkt[4:6], uint16(8+header.TCPMinimumSize))
	pkt[header.IPv6MinimumSize] = uint8(header.TCPProtocolNumber)
	pkt[header.IPv6MinimumSize+1] = 0
	off, proto, err := ipv6L4Offset(pkt)
	if err != nil {
		t.Fatalf("offset: %v", err)
	}
	if proto != uint8(header.TCPProtocolNumber) || off != header.IPv6MinimumSize+8 {
		t.Fatalf("off=%d proto=%d", off, proto)
	}
}

func TestIPv6SYNPolicyRejectEmitsICMPv6(t *testing.T) {
	t.Parallel()
	rec := &recordingConnectIPConn{}
	f := &packetForwarder{
		conn: rec,
		o: ConnectIPTCPForwarderOptions{
			AllowPrivateTargets: false,
		},
	}
	src := tcpip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})
	dst := tcpip.AddrFrom16([16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	pkt := buildIPv6TCPPacket(src, dst, 52001, 443, 1000, 0, header.TCPFlagSyn, 65535, nil, nil)
	f.handleReadPacket(context.Background(), pkt)
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.written) != 1 || !isICMPv6AdminProhibited(rec.written[0]) {
		t.Fatalf("expected icmpv6 admin prohibited, got %d packets", len(rec.written))
	}
}
