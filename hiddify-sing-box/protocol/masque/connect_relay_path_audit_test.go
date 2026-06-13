package masque

import (
	_ "embed"
	"strings"
	"testing"
)

//go:embed endpoint_server.go
var endpointServerRelayAuditSource string

// TestArchREF2EndpointServerRelayDelegate (REF2-5): endpoint adapter delegates relay to server handler.
func TestArchREF2EndpointServerRelayDelegate(t *testing.T) {
	t.Parallel()
	if strings.Contains(endpointServerRelayAuditSource, "RelayTCPTunnel") {
		t.Fatal("endpoint_server.go must not call RelayTCPTunnel directly (use server.HandleTCPConnectRequest)")
	}
	if strings.Contains(endpointServerRelayAuditSource, "forwarder") {
		t.Fatal("endpoint_server.go must not use L3b forwarder for CONNECT-stream")
	}
	if !strings.Contains(endpointServerRelayAuditSource, "server.HandleTCPConnectRequest") {
		t.Fatal("endpoint_server.go: missing server.HandleTCPConnectRequest delegate")
	}
	if !strings.Contains(endpointServerRelayAuditSource, "handleTCPConnectRequest") {
		t.Fatal("endpoint_server.go: missing handleTCPConnectRequest wrapper")
	}
}
