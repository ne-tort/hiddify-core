package forwarder

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
)

func TestBuildIPv4ICMPAdminProhibited(t *testing.T) {
	t.Parallel()
	orig, err := buildIPv4UDPPacket(
		netip.MustParseAddr("198.18.0.2"), 53000,
		netip.MustParseAddr("10.0.0.1"), 5201,
		[]byte("x"),
	)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	icmpPkt := BuildIPv4ICMPAdminProhibited(orig)
	if !isIPv4ICMPAdminProhibited(icmpPkt) {
		t.Fatalf("expected admin prohibited icmp len=%d", len(icmpPkt))
	}
}

func TestBuildICMPv6AdminProhibited(t *testing.T) {
	t.Parallel()
	src := netip.MustParseAddr("2001:db8::2")
	dst := netip.MustParseAddr("2001:db8::1")
	src16 := src.As16()
	dst16 := dst.As16()
	orig := make([]byte, 40)
	orig[0] = 6 << 4
	copy(orig[8:24], src16[:])
	copy(orig[24:40], dst16[:])
	orig[6] = 59
	icmpPkt := BuildICMPv6AdminProhibited(orig)
	if !isICMPv6AdminProhibited(icmpPkt) {
		t.Fatalf("expected icmpv6 admin prohibited len=%d", len(icmpPkt))
	}
}

func TestTCPForwarderPolicyRejectSendsICMPNotRST(t *testing.T) {
	t.Parallel()
	rec := &recordingConnectIPConn{}
	f := &packetForwarder{
		conn: rec,
		o: ConnectIPTCPForwarderOptions{
			AllowPrivateTargets: false,
		},
	}
	src := tcpip.AddrFrom4([4]byte{198, 18, 0, 2})
	dst := tcpip.AddrFrom4([4]byte{169, 254, 1, 1})
	pkt := BuildIPv4TCPPacket(src, dst, 52001, 443, 1000, 0, header.TCPFlagSyn, 65535, nil, nil)
	tc := header.TCP(pkt[20:])
	flow := tcp4Tuple{srcAddr: src, dstAddr: dst, srcPort: 52001, dstPort: 443}
	f.handleSyn(context.Background(), pkt, tc, flow)

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.written) != 1 {
		t.Fatalf("written=%d want 1", len(rec.written))
	}
	w := rec.written[0]
	if isIPv4ICMPAdminProhibited(w) {
		return
	}
	if len(w) >= 40 && w[9] == uint8(header.TCPProtocolNumber) {
		t.Fatal("policy reject sent TCP packet, want ICMP admin prohibited")
	}
	t.Fatalf("unexpected feedback len=%d proto=%d", len(w), w[9])
}

func TestIPv6PolicyDropEmitsICMPv6AdminProhibited(t *testing.T) {
	t.Parallel()
	rec := &recordingConnectIPConn{}
	f := &packetForwarder{
		conn: rec,
		o: ConnectIPTCPForwarderOptions{
			AllowPrivateTargets: false,
		},
	}
	src := netip.MustParseAddr("2001:db8::2")
	dst := netip.MustParseAddr("fe80::1")
	src16 := src.As16()
	dst16 := dst.As16()
	pkt := make([]byte, 40)
	pkt[0] = 6 << 4
	copy(pkt[8:24], src16[:])
	copy(pkt[24:40], dst16[:])
	pkt[6] = 59
	f.handleReadPacket(context.Background(), pkt)

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.written) != 1 {
		t.Fatalf("written=%d want 1", len(rec.written))
	}
	if !isICMPv6AdminProhibited(rec.written[0]) {
		t.Fatalf("expected icmpv6 admin prohibited len=%d", len(rec.written[0]))
	}
}
