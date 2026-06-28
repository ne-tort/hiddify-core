package masque

import "testing"

// TestGATEConnectIPProdNativeL3Eligible locks connect-ip-h3-tun profile eligibility (PROD-1).
func TestGATEConnectIPProdNativeL3Eligible(t *testing.T) {
	if !ConnectIPTunNativeL3Eligible("connect_ip", "connect_ip") {
		t.Fatal("connect_ip + tcp_transport=connect_ip must be native L3 eligible")
	}
	if ConnectIPTunNativeL3Eligible("connect_ip", "connect_stream") {
		t.Fatal("hybrid connect_stream must not wire native L3 (UDP fallback only)")
	}
	if ConnectIPTunNativeL3Eligible("connect_stream", "connect_ip") {
		t.Fatal("connect_stream transport must not wire native L3")
	}
}
