package masque

import (
	"net"
	"net/netip"
	"testing"
)

func TestMasqueOnwardTCPDialAddrInvalidHostFallsBackToJoinHostPort(t *testing.T) {
	got := MasqueOnwardTCPDialAddr("not-an-ip", 5201)
	want := net.JoinHostPort("not-an-ip", "5201")
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestMasqueOnwardTCPDialAddrPublicIPUsesHostPort(t *testing.T) {
	got := MasqueOnwardTCPDialAddr("203.0.113.1", 443)
	want := net.JoinHostPort("203.0.113.1", "443")
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestMasqueOnwardTCPDialAddrLoopback(t *testing.T) {
	got := MasqueOnwardTCPDialAddr("127.0.0.1", 1)
	want := net.JoinHostPort("127.0.0.1", "1")
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestMasqueOnwardTCPDialAddrBracketedIPv6(t *testing.T) {
	addr := netip.MustParseAddr("2001:db8::1")
	got := MasqueOnwardTCPDialAddr("["+addr.String()+"]", 443)
	want := net.JoinHostPort(addr.String(), "443")
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}
