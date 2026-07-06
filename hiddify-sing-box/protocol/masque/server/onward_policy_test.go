package server

import (
	"net/netip"
	"testing"
)

func TestOrderResolvedTCPAddrsPrefersIPv4(t *testing.T) {
	t.Parallel()
	aaaa := netip.MustParseAddr("2001:db8::1")
	aaaaFirst := netip.MustParseAddr("2001:db8::2")
	v4a := netip.MustParseAddr("203.0.113.10")
	v4b := netip.MustParseAddr("198.51.100.20")
	v4In6 := netip.MustParseAddr("::ffff:192.0.2.1")

	got := OrderResolvedTCPAddrs([]netip.Addr{aaaa, v4a, aaaaFirst, v4In6, v4b})
	want := []netip.Addr{v4a, netip.MustParseAddr("192.0.2.1"), v4b, aaaa, aaaaFirst}
	if len(got) != len(want) {
		t.Fatalf("len=%d want %d addrs=%v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("index %d: got %v want %v full=%v", i, got[i], want[i], got)
		}
	}
}

func TestResolveTCPTargetForDialUsesIPv4FirstFromOrdered(t *testing.T) {
	t.Parallel()
	ordered := OrderResolvedTCPAddrs([]netip.Addr{
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("203.0.113.5"),
	})
	if len(ordered) != 2 || !ordered[0].Is4() {
		t.Fatalf("order sanity: %v", ordered)
	}
	// ResolveTCPTargetForDial delegates to Addrs — verify literal path.
	got, err := ResolveTCPTargetAddrsForDial(t.Context(), "203.0.113.9", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].String() != "203.0.113.9" {
		t.Fatalf("literal: got %v", got)
	}
	chosen, err := ResolveTCPTargetForDial(t.Context(), "203.0.113.9", false)
	if err != nil || chosen != "203.0.113.9" {
		t.Fatalf("ResolveTCPTargetForDial: %q err=%v", chosen, err)
	}
}

func TestResolveTCPTargetAddrsAllowPrivateHostname(t *testing.T) {
	t.Parallel()
	got, err := ResolveTCPTargetAddrsForDial(t.Context(), "bench.local", true)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("allowPrivate hostname want nil addrs, got %v", got)
	}
	got, err = ResolveTCPTargetAddrsForDial(t.Context(), "127.0.0.1", true)
	if err != nil || len(got) != 1 || got[0].String() != "127.0.0.1" {
		t.Fatalf("allowPrivate literal: got %v err=%v", got, err)
	}
}
