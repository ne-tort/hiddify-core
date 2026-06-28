package masque

import (
	"testing"

	"github.com/sagernet/sing-box/protocol/tun"
)

// TestGATEConnectIPEndpointImplementsNativeL3Outbound ensures masque Endpoint satisfies tun inbound wire API (PROD-1).
func TestGATEConnectIPEndpointImplementsNativeL3Outbound(t *testing.T) {
	var _ tun.L3OverlayNativeOutbound = (*Endpoint)(nil)
}
