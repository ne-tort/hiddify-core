package masque

import (
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
