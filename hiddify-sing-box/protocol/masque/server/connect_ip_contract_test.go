package server

import (
	_ "embed"
	"strings"
	"testing"
)

//go:embed connect_ip.go
var connectIPGoSource string

// TestConnectIPTCPTerminationUsesForwarderNotRelay locks CLIENT-SERVER-CONTRACTS:
// CONNECT-IP TCP terminates in the S2 packet-plane forwarder, not relay.TCPTunnel.
func TestConnectIPTCPTerminationUsesForwarderNotRelay(t *testing.T) {
	t.Parallel()
	if strings.Contains(connectIPGoSource, "relay.TCPTunnel") {
		t.Fatal("CONNECT-IP route must not use relay.TCPTunnel")
	}
	if strings.Contains(connectIPGoSource, "relay/") {
		t.Fatal("CONNECT-IP route must not import protocol/masque/relay")
	}
	if !strings.Contains(connectIPGoSource, "fwd.RunConnectIPTCPPacketPlaneForwarder") {
		t.Fatal("CONNECT-IP route must terminate TCP via forwarder.RunConnectIPTCPPacketPlaneForwarder")
	}
}
