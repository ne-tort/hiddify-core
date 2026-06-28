package tun

import (
	"net/netip"
	"testing"

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
