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

// TestGATEConnectIPMidSessionMultiflowRecycle is P2-13 / F3-T6:
// ≥2 live TCP → server recycle + latch → same-session restore dials.
func TestGATEConnectIPMidSessionMultiflowRecycle(t *testing.T) {
	inttest.RunGATEConnectIPMidSessionMultiflowRecycle(t)
}

// TestGATEConnectIPMidSessionMultiflowRecycleH2 is P2-13 H2 smoke.
func TestGATEConnectIPMidSessionMultiflowRecycleH2(t *testing.T) {
	inttest.RunGATEConnectIPMidSessionMultiflowRecycleH2(t)
}

// TestGATEConnectIPMixedTCPUDPManyFlow is P3-3 / F3-G2:
// sticky TCP bulk + N UDP microflows on one plane; latch=false.
func TestGATEConnectIPMixedTCPUDPManyFlow(t *testing.T) {
	inttest.RunGATEConnectIPMixedTCPUDPManyFlow(t)
}

// TestGATEConnectIPMixedTCPUDPManyFlowH2 is P3-3 H2 smoke of mixed TCP+UDP.
func TestGATEConnectIPMixedTCPUDPManyFlowH2(t *testing.T) {
	inttest.RunGATEConnectIPMixedTCPUDPManyFlowH2(t)
}

// TestGATEConnectIPBenignHalfCloseMultiFlow is P3-4 / F3-T2:
// sticky bulk + benign plane half-close must not latch.
func TestGATEConnectIPBenignHalfCloseMultiFlow(t *testing.T) {
	inttest.RunGATEConnectIPBenignHalfCloseMultiFlow(t)
}

// TestGATEConnectIPBenignHalfCloseMultiFlowH2 is P3-4 H2 smoke.
func TestGATEConnectIPBenignHalfCloseMultiFlowH2(t *testing.T) {
	inttest.RunGATEConnectIPBenignHalfCloseMultiFlowH2(t)
}

// TestGATEConnectIPP4PlaneControlAlive is P6-B0: 4 bulk + 1 control on one H3 plane.
func TestGATEConnectIPP4PlaneControlAlive(t *testing.T) {
	inttest.RunGATEConnectIPP4PlaneControlAlive(t)
}

// TestGATEConnectIPP4PlaneControlAliveH2 is P6-B0 H2 counterpart.
func TestGATEConnectIPP4PlaneControlAliveH2(t *testing.T) {
	inttest.RunGATEConnectIPP4PlaneControlAliveH2(t)
}

// TestGATEConnectIPP4PlaneControlAliveTunCM is P6-B2c: sticky+4 via TunCM host path.
func TestGATEConnectIPP4PlaneControlAliveTunCM(t *testing.T) {
	inttest.RunGATEConnectIPP4PlaneControlAliveTunCM(t)
}
