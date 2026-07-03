package masque

import (
	"testing"

	"github.com/sagernet/sing-box/option"
)

// TestGATEConnectIPProdNativeL3Eligible locks connect-ip-h3-tun profile eligibility (PROD-1).
func TestGATEConnectIPProdNativeL3Eligible(t *testing.T) {
	if !ConnectIPTunNativeL3Eligible(option.MasqueDataplaneConnectIP) {
		t.Fatal("mode connect_ip must be native L3 eligible")
	}
	if ConnectIPTunNativeL3Eligible(option.MasqueDataplaneDefault) {
		t.Fatal("default dataplane must not wire native L3 (hybrid UDP/TCP split)")
	}
	if ConnectIPTunNativeL3Eligible("") {
		t.Fatal("empty dataplane must not wire native L3")
	}
}
