//go:build with_gvisor

package tun

import (
	"net/netip"
	"testing"
)

func TestOverlayStackEgress(t *testing.T) {
	broadcast := netip.MustParseAddr("255.255.255.255")
	prefixes := []netip.Prefix{netip.MustParsePrefix("172.30.99.0/24")}
	tunHost := netip.MustParseAddr("172.19.100.2")
	overlayDst := netip.MustParseAddr("172.30.99.2")
	var sent int
	send := func([]byte) error { sent++; return nil }

	if !overlayStackEgress(send, prefixes, broadcast, overlayDst) {
		t.Fatal("overlay route dst should use L3OverlaySend")
	}
	if sent != 1 {
		t.Fatalf("overlay send calls=%d want 1", sent)
	}
	if overlayStackEgress(send, prefixes, broadcast, tunHost) {
		t.Fatal("tun host dst should stay on tun write (SYN-ACK to app)")
	}
	if overlayStackEgress(send, prefixes, broadcast, broadcast) {
		t.Fatal("broadcast should stay on tun write path")
	}
	if overlayStackEgress(nil, prefixes, broadcast, overlayDst) {
		t.Fatal("nil send must not overlay")
	}
}
