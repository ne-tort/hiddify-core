package server

import (
	"context"
	"net/http"
	"net/netip"
	"testing"

	connectudp "github.com/sagernet/sing-box/transport/masque/connectudp"
)

func TestOrderResolvedTCPAddrsPrefersIPv4(t *testing.T) {
	t.Parallel()
	v6a := netip.MustParseAddr("2001:db8::1")
	v6b := netip.MustParseAddr("2001:db8::2")
	v4a := netip.MustParseAddr("203.0.113.10")
	v4b := netip.MustParseAddr("203.0.113.20")
	ordered := OrderResolvedTCPAddrs([]netip.Addr{v6a, v4b, v6b, v4a})
	if len(ordered) != 4 {
		t.Fatalf("len=%d", len(ordered))
	}
	if !ordered[0].Is4() || !ordered[1].Is4() || ordered[0].String() != "203.0.113.10" || ordered[1].String() != "203.0.113.20" {
		t.Fatalf("v4 first: %v", ordered)
	}
	if !ordered[2].Is6() || !ordered[3].Is6() {
		t.Fatalf("v6 after v4: %v", ordered)
	}
}

func TestResolveTCPTargetAddrsForDial_PublicLiteralIPv4(t *testing.T) {
	t.Parallel()
	addrs, err := ResolveTCPTargetAddrsForDial(context.Background(), "8.8.8.8", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 1 || addrs[0].String() != "8.8.8.8" {
		t.Fatalf("addrs=%v", addrs)
	}
}

func TestResolveTCPTargetAddrsForDial_PrivateLiteralDenied(t *testing.T) {
	t.Parallel()
	_, err := ResolveTCPTargetAddrsForDial(context.Background(), "10.0.0.1", false)
	if err == nil {
		t.Fatal("expected private denied")
	}
}

func TestResolveTCPTargetAddrsForDial_PrivateLiteralAllowed(t *testing.T) {
	t.Parallel()
	addrs, err := ResolveTCPTargetAddrsForDial(context.Background(), "10.0.0.1", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 1 || addrs[0].String() != "10.0.0.1" {
		t.Fatalf("addrs=%v", addrs)
	}
}

func TestGATEConnectStreamOnwardHostnamePassthroughNoEgressDNS(t *testing.T) {
	t.Parallel()
	addrs, err := ResolveTCPTargetAddrsForDial(context.Background(), "example.com", true)
	if err != nil {
		t.Fatal(err)
	}
	if addrs != nil {
		t.Fatalf("hostname must passthrough without MASQUE egress DNS, got %v", addrs)
	}
}

func TestConnectStreamResolveHTTPStatus(t *testing.T) {
	t.Parallel()
	if ConnectStreamResolveHTTPStatus(connectudp.ErrPrivateTargetDenied) != http.StatusForbidden {
		t.Fatal("private target -> 403")
	}
	if ConnectStreamResolveHTTPStatus(ErrTCPTargetResolveFailed) != http.StatusBadGateway {
		t.Fatal("resolve fail -> 502")
	}
}

func TestResolveTCPTargetAddrsForDial_LocalhostDenied(t *testing.T) {
	t.Parallel()
	_, err := ResolveTCPTargetAddrsForDial(context.Background(), "localhost", false)
	if err != connectudp.ErrPrivateTargetDenied {
		t.Fatalf("err=%v", err)
	}
}
