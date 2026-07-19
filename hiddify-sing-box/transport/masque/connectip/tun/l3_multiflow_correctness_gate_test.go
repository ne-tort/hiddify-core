package tun

import (
	"testing"
)

// TestGATEConnectIPMultiFlowCorrectnessTrack documents multi-flow upload as
// DOCUMENTED-DEFERRED (F3-T3 / G4 / P3-1): not a hard fairness SLO.
//
// Known symptoms (2026-06-28): iperf -P 2 ~1 Mbit/s; 2× parallel 524+0;
// sequential each ~524. Root: single LoopIn / one MASQUE session — product model.
// Do not use -P 2+ as upload KPI workaround. DualFlow/MultiShort = liveness, not fairness.
func TestGATEConnectIPMultiFlowCorrectnessTrack(t *testing.T) {
	t.Log("multi-flow fairness: DOCUMENTED-DEFERRED (F3-T3) — no hard floor")
	t.Log("KPI path: single-flow tcp_up only; reopen only with pump/FC attribution A/B")
	t.Log("symptom archive: concurrent upload flows do not sum; second may starve")
	t.Log("liveness contract: DualFlow + MultiShort + TCP churn (not fairness share)")
}
