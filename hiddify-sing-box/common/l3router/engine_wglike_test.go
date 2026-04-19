package l3router

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestMemEngineWGAllowedIPsForward(t *testing.T) {
	e := NewMemEngine()
	e.SetPacketFilter(false)
	e.UpsertRoute(Route{
		PeerID:          1,
		User:            "u1",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
	})
	e.UpsertRoute(Route{
		PeerID:          2,
		User:            "u2",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.0.1.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.0.1.0/24")},
	})
	pkt := makeIPv4Packet([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 1, 2})
	d := e.HandleIngressPeer(pkt, PeerID(1))
	if d.Action != ActionForward || d.EgressPeerID != PeerID(2) {
		t.Fatalf("unexpected decision: %+v", d)
	}
}

func TestMemEngineWGAllowedIPsNoLoopDrop(t *testing.T) {
	e := NewMemEngine()
	e.SetPacketFilter(false)
	e.UpsertRoute(Route{
		PeerID:          1,
		User:            "u1",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
	})
	pkt := makeIPv4Packet([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 3})
	d := e.HandleIngressPeer(pkt, PeerID(1))
	if d.Action != ActionDrop || d.DropReason != DropNoEgressRoute {
		t.Fatalf("expected no-loop drop, got %+v", d)
	}
}

func TestMemEngineFilterSourceDrop(t *testing.T) {
	e := NewMemEngine()
	e.SetPacketFilter(true)
	e.UpsertRoute(Route{
		PeerID:          1,
		User:            "u1",
		FilterSourceIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
		AllowedIPs:      []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
	})
	e.UpsertRoute(Route{
		PeerID:     2,
		User:       "u2",
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.0.1.0/24")},
	})
	pkt := makeIPv4Packet([4]byte{192, 168, 1, 1}, [4]byte{10, 0, 1, 2})
	d := e.HandleIngressPeer(pkt, PeerID(1))
	if d.Action != ActionDrop || d.DropReason != DropFilterSource {
		t.Fatalf("expected filter source drop, got %+v", d)
	}
}

func makeIPv4Packet(src, dst [4]byte) []byte {
	pkt := make([]byte, 20)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	return pkt
}
