package l3routerendpoint

import (
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestParseRouteOptions(t *testing.T) {
	route, err := ParseRouteOptions(option.L3RouterPeerOptions{
		PeerID:               10,
		User:                 "owner-a",
		FilterSourceIPs:      []string{"10.10.0.0/24"},
		FilterDestinationIPs: []string{"10.20.0.0/24"},
		AllowedIPs:           []string{"10.30.0.0/24"},
	})
	if err != nil {
		t.Fatalf("ParseRouteOptions: %v", err)
	}
	if route.PeerID != 10 || route.User != "owner-a" {
		t.Fatalf("unexpected parsed route: %+v", route)
	}
	if len(route.FilterSourceIPs) != 1 || len(route.FilterDestinationIPs) != 1 || len(route.AllowedIPs) != 1 {
		t.Fatalf("unexpected prefixes count: %+v", route)
	}
}

func TestParseRouteOptionsInvalidPrefix(t *testing.T) {
	_, err := ParseRouteOptions(option.L3RouterPeerOptions{
		PeerID:     11,
		User:       "u",
		AllowedIPs: []string{"not-a-prefix"},
	})
	if err == nil {
		t.Fatal("expected parse error for invalid prefix")
	}
	if !strings.Contains(err.Error(), "allowed_ips") {
		t.Fatalf("expected contextual field name in error, got: %v", err)
	}
}

func TestParseRouteOptionsDeduplicatesAndMasks(t *testing.T) {
	route, err := ParseRouteOptions(option.L3RouterPeerOptions{
		PeerID:          12,
		User:            "owner-b",
		FilterSourceIPs: []string{"10.30.0.0/24"},
		AllowedIPs:      []string{"10.30.0.7/24", "10.30.0.0/24"},
	})
	if err != nil {
		t.Fatalf("ParseRouteOptions: %v", err)
	}
	if len(route.AllowedIPs) != 1 {
		t.Fatalf("expected duplicate prefixes to be deduplicated, got %d", len(route.AllowedIPs))
	}
	if route.AllowedIPs[0].String() != "10.30.0.0/24" {
		t.Fatalf("expected masked prefix, got %s", route.AllowedIPs[0].String())
	}
}

func TestValidateRouteRequiresUser(t *testing.T) {
	route, err := ParseRouteOptions(option.L3RouterPeerOptions{
		PeerID:     13,
		User:       "",
		AllowedIPs: []string{"10.40.0.0/24"},
	})
	if err != nil {
		t.Fatalf("ParseRouteOptions: %v", err)
	}
	if err := ValidateRoute(route); err == nil {
		t.Fatal("expected validation error for missing user")
	}
}
