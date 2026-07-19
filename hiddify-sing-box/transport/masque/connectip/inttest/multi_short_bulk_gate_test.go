//go:build masque_inttest_heavy

package inttest_test

import (
	"testing"

	"github.com/sagernet/sing-box/transport/masque/connectip/inttest"
)

// TestGATEConnectIPMultiShortTCPBulkNoRecycleLatch is P1-4 / F3-T1:
// N short TCP + 1 bulk on one plane; siblings survive; no recycle latch.
func TestGATEConnectIPMultiShortTCPBulkNoRecycleLatch(t *testing.T) {
	inttest.RunGATEConnectIPMultiShortTCPBulkNoRecycleLatch(t)
}

// TestGATEConnectIPMultiShortTCPBulkNoRecycleLatchH2 is P1-9 / F3-T4 short-FIN smoke on H2.
func TestGATEConnectIPMultiShortTCPBulkNoRecycleLatchH2(t *testing.T) {
	inttest.RunGATEConnectIPMultiShortTCPBulkNoRecycleLatchH2(t)
}

// TestGATEConnectIPDualFlowIperfRControlH2 is P1-9 dual concurrent TCP on one H2 CONNECT-IP plane.
func TestGATEConnectIPDualFlowIperfRControlH2(t *testing.T) {
	inttest.RunGATEConnectIPDualFlowIperfRControlH2(t)
}

// TestGATEConnectIPTCPConnectCloseChurn is P2-12 / F3-T5:
// sequential TCP dial/close generations on one plane; sticky bulk survives; latch=false.
func TestGATEConnectIPTCPConnectCloseChurn(t *testing.T) {
	inttest.RunGATEConnectIPTCPConnectCloseChurn(t)
}

// TestGATEConnectIPTCPConnectCloseChurnH2 is P2-12 H2 smoke of sequential TCP churn.
func TestGATEConnectIPTCPConnectCloseChurnH2(t *testing.T) {
	inttest.RunGATEConnectIPTCPConnectCloseChurnH2(t)
}
