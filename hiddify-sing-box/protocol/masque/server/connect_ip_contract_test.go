package server

import (
	_ "embed"
	"strings"
	"testing"
)

//go:embed connect_ip_route.go
var connectIPGoSource string

// TestConnectIPRouteUsesPacketPlaneNotRelayTCPTunnel locks CIP = IP transport.
func TestConnectIPRouteUsesPacketPlaneNotRelayTCPTunnel(t *testing.T) {
	t.Parallel()
	if strings.Contains(connectIPGoSource, "relay.TCPTunnel") {
		t.Fatal("CONNECT-IP route must not use relay.TCPTunnel")
	}
	if strings.Contains(connectIPGoSource, "relay/") {
		t.Fatal("CONNECT-IP route must not import protocol/masque/relay")
	}
	if !strings.Contains(connectIPGoSource, "runConnectIPPacketEgress") {
		t.Fatal("CONNECT-IP route must prefer packet egress (RFC §7.2)")
	}
	if !strings.Contains(connectIPGoSource, "RunConnectIPPacketPlaneRelay") &&
		!strings.Contains(connectIPGoSource, "OpenConnectIPServerPacketDevice") {
		t.Fatal("CONNECT-IP route must wire packet plane / TUN open")
	}
	// terminate remains available as explicit stub, not identity
	if !strings.Contains(connectIPGoSource, "runConnectIPTerminateStub") {
		t.Fatal("CONNECT-IP route must keep terminate stub for lab egress=terminate")
	}
}
