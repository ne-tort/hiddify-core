package tun

import (
	"encoding/binary"
	"net/netip"
	"testing"

	connectip "github.com/quic-go/connect-ip-go"
	fwd "github.com/sagernet/sing-box/transport/masque/forwarder"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
)

func TestOverlayNATEgressSNAT(t *testing.T) {
	tunHost := netip.MustParseAddr("172.19.100.2")
	wire := netip.MustParseAddr("198.18.0.1")
	dst := netip.MustParseAddr("198.18.0.99")
	pkt := []byte{
		0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
		172, 19, 100, 2,
		198, 18, 0, 99,
	}
	nat := OverlayNAT{TunHost: tunHost, WireLocal: wire}
	out := nat.SNATEgress(pkt)
	got, ok := ipv4Source(out)
	if !ok || got != wire {
		t.Fatalf("SNAT src want %s got %v ok=%v", wire, got, ok)
	}
	gotDst, _ := ipv4Destination(out)
	if gotDst != dst {
		t.Fatalf("SNAT dst unchanged want %s got %s", dst, gotDst)
	}
}

func TestOverlayNATEgressInPlaceSNAT(t *testing.T) {
	tunHost := netip.MustParseAddr("172.19.100.2")
	wire := netip.MustParseAddr("198.18.0.1")
	pkt := []byte{
		0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
		172, 19, 100, 2,
		198, 18, 0, 99,
	}
	before := append([]byte(nil), pkt...)
	nat := OverlayNAT{TunHost: tunHost, WireLocal: wire}
	nat.SNATEgressInPlace(pkt)
	got, ok := ipv4Source(pkt)
	if !ok || got != wire {
		t.Fatalf("in-place SNAT src want %s got %v ok=%v", wire, got, ok)
	}
	if len(before) != len(pkt) {
		t.Fatalf("length changed: before=%d after=%d", len(before), len(pkt))
	}
}

// TestOverlayNATPreservesTOSByte locks P2-11 / F4-07: SNAT+DNAT rewrite addresses only;
// IPv4 TOS (DSCP+ECN) must stay bit-identical (not S2 rebuild TOS=0).
func TestOverlayNATPreservesTOSByte(t *testing.T) {
	const tos = byte(0xB9) // DSCP EF (46<<2) | ECT(1)
	tunHost := netip.MustParseAddr("172.19.100.2")
	wire := netip.MustParseAddr("198.18.0.1")
	pkt := []byte{
		0x45, tos, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
		172, 19, 100, 2,
		198, 18, 0, 99,
	}
	nat := OverlayNAT{TunHost: tunHost, WireLocal: wire}

	out := nat.SNATEgress(append([]byte(nil), pkt...))
	if out[1] != tos {
		t.Fatalf("SNATEgress TOS=%#02x want %#02x", out[1], tos)
	}
	nat.SNATEgressInPlace(pkt)
	if pkt[1] != tos {
		t.Fatalf("SNATEgressInPlace TOS=%#02x want %#02x", pkt[1], tos)
	}

	ingress := []byte{
		0x45, tos, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
		198, 18, 0, 2,
		198, 18, 0, 1,
	}
	nat.DNATIngressInPlace(ingress)
	if ingress[1] != tos {
		t.Fatalf("DNATIngressInPlace TOS=%#02x want %#02x", ingress[1], tos)
	}
}

func TestOverlayNATIngressInPlaceDNAT(t *testing.T) {
	tunHost := netip.MustParseAddr("172.19.100.2")
	wire := netip.MustParseAddr("198.18.0.1")
	pkt := []byte{
		0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
		198, 18, 0, 2,
		198, 18, 0, 1,
	}
	nat := OverlayNAT{TunHost: tunHost, WireLocal: wire}
	nat.DNATIngressInPlace(pkt)
	gotDst, ok := ipv4Destination(pkt)
	if !ok || gotDst != tunHost {
		t.Fatalf("in-place DNAT dst want %s got %v ok=%v", tunHost, gotDst, ok)
	}
}

func TestOverlayNATHairpin(t *testing.T) {
	tunHost := netip.MustParseAddr("172.19.100.2")
	wire := netip.MustParseAddr("198.18.0.1")
	virt := netip.MustParseAddr("198.18.0.99")
	loop := netip.MustParseAddr("127.0.0.1")
	pkt := []byte{
		0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
		172, 19, 100, 2,
		198, 18, 0, 99,
	}
	nat := OverlayNAT{TunHost: tunHost, WireLocal: wire, VirtTarget: virt, WireTarget: loop}
	out := nat.SNATEgress(pkt)
	src, _ := ipv4Source(out)
	dst, _ := ipv4Destination(out)
	if src != wire || dst != loop {
		t.Fatalf("hairpin SNAT want src=%s dst=%s got src=%s dst=%s", wire, loop, src, dst)
	}
	reply := []byte{
		0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
		127, 0, 0, 1,
		198, 18, 0, 1,
	}
	back := nat.DNATIngress(reply)
	src, _ = ipv4Source(back)
	dst, _ = ipv4Destination(back)
	if src != virt || dst != tunHost {
		t.Fatalf("hairpin DNAT want src=%s dst=%s got src=%s dst=%s", virt, tunHost, src, dst)
	}
}

func TestOverlayNATIngressDNATWireLocal(t *testing.T) {
	tunHost := netip.MustParseAddr("172.19.100.2")
	wire := netip.MustParseAddr("198.18.0.1")
	src := netip.MustParseAddr("10.0.0.1")
	pkt := []byte{
		0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
		10, 0, 0, 1,
		198, 18, 0, 1,
	}
	nat := OverlayNAT{TunHost: tunHost, WireLocal: wire}
	out := nat.DNATIngress(pkt)
	got, ok := ipv4Destination(out)
	if !ok || got != tunHost {
		t.Fatalf("DNAT dst want %s got %v ok=%v", tunHost, got, ok)
	}
	gotSrc, _ := ipv4Source(out)
	if gotSrc != src {
		t.Fatalf("DNAT src unchanged want %s got %s", src, gotSrc)
	}
}


func TestOverlayNATEgressSNATUploadPayload(t *testing.T) {
	tunHost := netip.MustParseAddr("172.19.100.2")
	wire := netip.MustParseAddr("198.18.0.1")
	server := netip.MustParseAddr("172.30.99.2")
	payload := make([]byte, 1380)
	for i := range payload {
		payload[i] = byte(i)
	}
	pkt := fwd.BuildIPv4TCPPacket(
		tcpip.AddrFrom4(tunHost.As4()),
		tcpip.AddrFrom4(server.As4()),
		40000, 5201,
		1000, 2000,
		header.TCPFlagPsh|header.TCPFlagAck,
		65535, payload, nil,
	)
	nat := OverlayNAT{TunHost: tunHost, WireLocal: wire}
	out := nat.SNATEgress(pkt)
	src, _ := ipv4Source(out)
	if src != wire {
		t.Fatalf("SNAT src=%v want %v", src, wire)
	}
	if !validIPv4TCPChecksum(out) {
		t.Fatal("SNAT upload payload: invalid TCP checksum after rewrite")
	}
}

// TestOverlayNATIngressDNATICMPQuotedPTB (P1-8): PTB composed from post-SNAT IP must expose
// TunHost in the quoted header after DNATIngress (host PMTUD view).
func TestOverlayNATIngressDNATICMPQuotedPTB(t *testing.T) {
	tunHost := netip.MustParseAddr("172.19.100.2")
	wire := netip.MustParseAddr("198.18.0.1")
	peer := netip.MustParseAddr("198.18.0.99")
	orig := make([]byte, 40)
	orig[0] = 0x45
	orig[1] = 0x00
	binary.BigEndian.PutUint16(orig[2:4], 40)
	orig[8] = 64
	orig[9] = 6 // TCP
	copy(orig[12:16], tunHost.AsSlice())
	copy(orig[16:20], peer.AsSlice())
	// Fake TCP ports (8 bytes after IP hdr for ICMP quote).
	binary.BigEndian.PutUint16(orig[20:22], 40000)
	binary.BigEndian.PutUint16(orig[22:24], 5201)

	nat := OverlayNAT{TunHost: tunHost, WireLocal: wire}
	wireView := nat.SNATEgress(append([]byte(nil), orig...))
	src, _ := ipv4Source(wireView)
	if src != wire {
		t.Fatalf("precondition SNAT src=%v want %v", src, wire)
	}

	ptb, err := connectip.ComposeICMPPacketTooBig(wireView, 1280)
	if err != nil {
		t.Fatalf("ComposeICMPPacketTooBig: %v", err)
	}
	// Before fix: outer DNAT only — quoted src stays WireLocal.
	hostView := nat.DNATIngress(append([]byte(nil), ptb...))
	outerDst, ok := ipv4Destination(hostView)
	if !ok || outerDst != tunHost {
		t.Fatalf("outer DNAT dst want %s got %v ok=%v", tunHost, outerDst, ok)
	}
	ihl := int(hostView[0]&0x0f) * 4
	quote := hostView[ihl+8:]
	if len(quote) < 20 {
		t.Fatalf("quoted IP too short: %d", len(quote))
	}
	qSrc, ok := ipv4Source(quote)
	if !ok || qSrc != tunHost {
		t.Fatalf("quoted src want TunHost %s got %v ok=%v (wire=%s)", tunHost, qSrc, ok, wire)
	}
	qDst, _ := ipv4Destination(quote)
	if qDst != peer {
		t.Fatalf("quoted dst want peer %s got %s", peer, qDst)
	}
}

func TestOverlayNATIngressDNATICMPQuotedHairpin(t *testing.T) {
	tunHost := netip.MustParseAddr("172.19.100.2")
	wire := netip.MustParseAddr("198.18.0.1")
	virt := netip.MustParseAddr("198.18.0.99")
	loop := netip.MustParseAddr("127.0.0.1")
	orig := make([]byte, 40)
	orig[0] = 0x45
	binary.BigEndian.PutUint16(orig[2:4], 40)
	orig[8] = 64
	orig[9] = 17 // UDP
	copy(orig[12:16], tunHost.AsSlice())
	copy(orig[16:20], virt.AsSlice())
	binary.BigEndian.PutUint16(orig[20:22], 5000)
	binary.BigEndian.PutUint16(orig[22:24], 5201)

	nat := OverlayNAT{TunHost: tunHost, WireLocal: wire, VirtTarget: virt, WireTarget: loop}
	wireView := nat.SNATEgress(append([]byte(nil), orig...))
	ptb, err := connectip.ComposeICMPPacketTooBig(wireView, 1280)
	if err != nil {
		t.Fatalf("ComposeICMPPacketTooBig: %v", err)
	}
	hostView := nat.DNATIngress(ptb)
	ihl := int(hostView[0]&0x0f) * 4
	quote := hostView[ihl+8:]
	qSrc, _ := ipv4Source(quote)
	qDst, _ := ipv4Destination(quote)
	if qSrc != tunHost || qDst != virt {
		t.Fatalf("quoted want src=%s dst=%s got src=%s dst=%s", tunHost, virt, qSrc, qDst)
	}
}

