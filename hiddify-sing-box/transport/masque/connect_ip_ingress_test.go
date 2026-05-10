package masque

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestDeliverIPv4UDPBridgedIngress(t *testing.T) {
	s := &coreSession{}

	sub1 := s.registerUDPIngressSubscriber()
	defer s.unregisterUDPIngressSubscriber(sub1)
	sub2 := s.registerUDPIngressSubscriber()
	defer s.unregisterUDPIngressSubscriber(sub2)

	src := netip.MustParseAddr("10.200.0.2")
	dst := netip.MustParseAddr("198.18.0.2")
	pkt, err := buildIPv4UDPPacket(src, 53, dst, 53000, []byte("x"))
	if err != nil {
		t.Fatalf("build udp: %v", err)
	}

	if ok := s.deliverIPv4UDPBridgedIngress(pkt); !ok {
		t.Fatal("expected deliver with subscribers")
	}
	for i, sub := range []*udpIngressSubscriber{sub1, sub2} {
		select {
		case got := <-sub.ch:
			if len(got) != len(pkt) {
				t.Fatalf("subscriber %d: len got=%d want=%d", i, len(got), len(pkt))
			}
		default:
			t.Fatalf("subscriber %d: missing packet", i)
		}
	}
}

func TestDeliverIPv4UDPBridgedIngressNoSubscribers(t *testing.T) {
	s := &coreSession{}
	src := netip.MustParseAddr("10.200.0.2")
	dst := netip.MustParseAddr("198.18.0.2")
	pkt, err := buildIPv4UDPPacket(src, 53, dst, 53000, []byte("x"))
	if err != nil {
		t.Fatalf("build udp: %v", err)
	}
	if ok := s.deliverIPv4UDPBridgedIngress(pkt); ok {
		t.Fatal("expected no delivery without subscribers")
	}
}

func TestClassifyIPv4UDPBridgeCandidate(t *testing.T) {
	src := netip.MustParseAddr("10.200.0.2")
	dst := netip.MustParseAddr("198.18.0.2")
	valid, err := buildIPv4UDPPacket(src, 53, dst, 53000, []byte("x"))
	if err != nil {
		t.Fatalf("build udp: %v", err)
	}
	br, mf := classifyIPv4UDPBridgeCandidate(valid)
	if !br || mf {
		t.Fatalf("valid packet: bridgeable=%v malformed=%v", br, mf)
	}

	pkt := append([]byte(nil), valid...)
	udpOff := 20
	// UDP length < 8 is rejected by parseIPv4UDPPacketOffsets (corrupt / nonsensical frame).
	binary.BigEndian.PutUint16(pkt[udpOff+4:udpOff+6], 4)
	br, mf = classifyIPv4UDPBridgeCandidate(pkt)
	if br || !mf {
		t.Fatalf("udp length < 8: bridgeable=%v malformed=%v (want bridgeable=false malformed=true)", br, mf)
	}

	tcp := append([]byte(nil), valid...)
	tcp[9] = 6 // TCP
	br, mf = classifyIPv4UDPBridgeCandidate(tcp)
	if br || mf {
		t.Fatalf("tcp proto: bridgeable=%v malformed=%v", br, mf)
	}

	mfPkt := append([]byte(nil), valid...)
	binary.BigEndian.PutUint16(mfPkt[6:8], 0x2000) // More Fragments; offset 0
	br, mf = classifyIPv4UDPBridgeCandidate(mfPkt)
	if br || mf {
		t.Fatalf("ipv4 udp first fragment MF: bridgeable=%v malformed=%v (want false,false)", br, mf)
	}
	if _, _, _, _, perr := parseIPv4UDPPacketOffsets(mfPkt); perr == nil {
		t.Fatal("parseIPv4UDPPacketOffsets: expected error for MF fragment")
	}

	offPkt := append([]byte(nil), valid...)
	binary.BigEndian.PutUint16(offPkt[6:8], 1) // non-zero fragment offset (8 bytes)
	br, mf = classifyIPv4UDPBridgeCandidate(offPkt)
	if br || mf {
		t.Fatalf("ipv4 udp non-first fragment: bridgeable=%v malformed=%v (want false,false)", br, mf)
	}
	if _, _, _, _, perr := parseIPv4UDPPacketOffsets(offPkt); perr == nil {
		t.Fatal("parseIPv4UDPPacketOffsets: expected error for non-zero fragment offset")
	}
}
