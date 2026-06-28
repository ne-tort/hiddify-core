//go:build with_gvisor

package inttest_test

import (
	"testing"

	"github.com/sagernet/sing-box/transport/masque/connectip/inttest"
)

func TestGATEConnectIPDualFlowIperfRControl(t *testing.T) {
	inttest.RunGATEConnectIPDualFlowIperfRControl(t)
}

// TestGATEConnectIPTunCMDualFlowIperfRControl is the Docker tun0/CM analog; CM router serializes
// lazy-handshake dials — run with -count=1 when validating TUN egress priority regressions.
func TestGATEConnectIPTunCMDualFlowIperfRControl(t *testing.T) {
	t.Parallel()
	inttest.RunGATEConnectIPTunCMDualFlowIperfRControl(t)
}
