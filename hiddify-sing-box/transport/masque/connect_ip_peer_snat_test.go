package masque

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestRewriteConnectIPOutgoingPeerDstIPv4(t *testing.T) {
	t.Parallel()
	peer := netip.MustParseAddr("198.18.0.1")
	peerPrefixes := []netip.Prefix{netip.MustParsePrefix("198.18.0.1/32")}
	pkt := make([]byte, 40)
	pkt[0] = 0x45
	pkt[1] = 0
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[9] = 6
	src4 := netip.MustParseAddr("163.5.180.181").As4()
	dst4 := netip.MustParseAddr("203.0.113.1").As4()
	copy(pkt[12:16], src4[:])
	copy(pkt[16:20], dst4[:])
	pkt[20] = 0x50
	setIPv4HeaderChecksum(pkt[:20])
	binary.BigEndian.PutUint16(pkt[36:38], 0)
	csum := transportChecksumIPv4(pkt[:20], pkt[20:], 6)
	binary.BigEndian.PutUint16(pkt[36:38], csum)

	out := RewriteConnectIPOutgoingPeerDst(pkt, peerPrefixes)
	if got := netip.AddrFrom4([4]byte(out[16:20])); got != peer {
		t.Fatalf("dst after rewrite: got %s want %s", got, peer)
	}
}

func TestRewriteConnectIPOutgoingPeerDstIPv6WhenIPv4ListedFirst(t *testing.T) {
	t.Parallel()
	peerPrefixes := []netip.Prefix{
		netip.MustParsePrefix("198.18.0.1/32"),
		netip.MustParsePrefix("fd00::1/128"),
	}
	wantPeer := netip.MustParseAddr("fd00::1")
	pkt := make([]byte, 60)
	pkt[0] = 0x60
	pkt[6] = 6
	pkt[7] = 64
	binary.BigEndian.PutUint16(pkt[4:6], uint16(len(pkt)-40))
	src := netip.MustParseAddr("2001:db8::1").As16()
	dstWrong := netip.MustParseAddr("2001:db8::2").As16()
	copy(pkt[8:24], src[:])
	copy(pkt[24:40], dstWrong[:])
	off := 40
	pkt[off] = 20
	pkt[off+1] = 1
	pkt[off+2] = 0
	pkt[off+3] = 80
	binary.BigEndian.PutUint16(pkt[off+4:off+6], 20)
	binary.BigEndian.PutUint16(pkt[off+16:off+18], 0)
	csum := transportChecksumIPv6(pkt[:40], pkt[off:], 6)
	binary.BigEndian.PutUint16(pkt[off+16:off+18], csum)

	out := RewriteConnectIPOutgoingPeerDst(pkt, peerPrefixes)
	got := netip.AddrFrom16([16]byte(out[24:40]))
	if got != wantPeer {
		t.Fatalf("IPv6 dst after rewrite: got %s want %s", got, wantPeer)
	}
}
