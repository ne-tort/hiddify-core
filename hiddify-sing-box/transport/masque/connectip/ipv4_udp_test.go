package connectip

import (
	"bytes"
	"net/netip"
	"testing"
)

func TestBuildAndParseIPv4UDPPacket(t *testing.T) {
	src := netip.MustParseAddr("198.18.0.2")
	dst := netip.MustParseAddr("10.200.0.2")
	payload := []byte("hello-masque")
	packet, err := BuildIPv4UDPPacket(src, 53000, dst, 5601, payload)
	if err != nil {
		t.Fatalf("build packet: %v", err)
	}
	gotPayload, gotSrc, gotSrcPort, err := ParseIPv4UDPPacket(packet)
	if err != nil {
		t.Fatalf("parse packet: %v", err)
	}
	if gotSrc != src {
		t.Fatalf("unexpected src: %s", gotSrc)
	}
	if gotSrcPort != 53000 {
		t.Fatalf("unexpected src port: %d", gotSrcPort)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Fatalf("unexpected payload: %q", gotPayload)
	}
}

func TestBuildIPv4UDPPacketInplaceReusesBuffer(t *testing.T) {
	src := netip.MustParseAddr("198.18.0.2")
	dst := netip.MustParseAddr("10.200.0.2")
	initial := make([]byte, 0, 2048)
	packetA, err := BuildIPv4UDPPacketInplace(initial, src, 53000, dst, 5601, []byte("a"))
	if err != nil {
		t.Fatalf("first packet build: %v", err)
	}
	packetB, err := BuildIPv4UDPPacketInplace(packetA[:0], src, 53000, dst, 5601, []byte("bbbb"))
	if err != nil {
		t.Fatalf("second packet build: %v", err)
	}
	if len(packetB) != 32 {
		t.Fatalf("unexpected packet size: got=%d want=32", len(packetB))
	}
	if &packetA[:1][0] != &packetB[:1][0] {
		t.Fatal("expected in-place builder to reuse caller-provided capacity")
	}
}
