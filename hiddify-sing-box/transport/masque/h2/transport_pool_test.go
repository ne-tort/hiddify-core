package h2

import "testing"

func TestSeparateTransportRolesAreDistinct(t *testing.T) {
	if len(SeparateTransportRoles) != 2 {
		t.Fatalf("expected exactly two H2 transport pools, got %d", len(SeparateTransportRoles))
	}
	if SeparateTransportRoles[0] == SeparateTransportRoles[1] {
		t.Fatal("UDP and CONNECT-stream pools must not share a role")
	}
	if got, want := TransportUDP.SessionFieldName(), "H2UDPTransport"; got != want {
		t.Fatalf("TransportUDP field: got %q want %q", got, want)
	}
	if got, want := TransportConnectStream.SessionFieldName(), "H2ConnectStreamTransport"; got != want {
		t.Fatalf("TransportConnectStream field: got %q want %q", got, want)
	}
}
