//go:build with_gvisor

package tun

import (
	"net/netip"
	"testing"

	"github.com/sagernet/gvisor/pkg/tcpip/stack"
)

func TestOverlayTCPRouteMatchesLocalOrRemote(t *testing.T) {
	prefixes := []netip.Prefix{netip.MustParsePrefix("198.18.0.99/32")}
	f := &TCPForwarder{l3OverlayPrefixes: prefixes}

	server := stack.TransportEndpointID{
		LocalAddress:  AddressFromAddr(netip.MustParseAddr("198.18.0.99")),
		LocalPort:     5201,
		RemoteAddress: AddressFromAddr(netip.MustParseAddr("172.19.100.2")),
		RemotePort:    40000,
	}
	if !f.overlayTCPRoute(server) {
		t.Fatal("outbound to overlay server should match local address")
	}

	client := stack.TransportEndpointID{
		LocalAddress:  AddressFromAddr(netip.MustParseAddr("172.19.100.2")),
		LocalPort:     40000,
		RemoteAddress: AddressFromAddr(netip.MustParseAddr("198.18.0.99")),
		RemotePort:    5201,
	}
	if !f.overlayTCPRoute(client) {
		t.Fatal("flow with overlay remote should match remote address")
	}

	other := stack.TransportEndpointID{
		LocalAddress:  AddressFromAddr(netip.MustParseAddr("10.0.0.1")),
		LocalPort:     443,
		RemoteAddress: AddressFromAddr(netip.MustParseAddr("10.0.0.2")),
		RemotePort:    40000,
	}
	if f.overlayTCPRoute(other) {
		t.Fatal("non-overlay flow should not match")
	}
}
