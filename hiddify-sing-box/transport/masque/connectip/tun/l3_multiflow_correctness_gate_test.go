package tun

import (
	"testing"
)

// TestGATEConnectIPMultiFlowCorrectnessTrack documents multi-flow upload correctness as a
// separate track from single-flow upload KPI (DoD ≥1000 Mbit/s one TCP).
//
// Probe: docker/masque-perf-lab/_bench_tcp_parallel_upload.py
// Env: BENCH_IPERF_PARALLEL_STREAMS, BENCH_CONNECT_IP_TUN_UPLOAD_ONLY
//
// Known symptoms (2026-06-28): iperf -P 2 ~1 Mbit/s; 2× parallel iperf 524+0;
// sequential flows each hit 524. Root: single LoopIn pump / one MASQUE session cap,
// not per-thread scaling. Fix belongs to fairness/multiplex PR, not upload KPI path.
func TestGATEConnectIPMultiFlowCorrectnessTrack(t *testing.T) {
	t.Log("multi-flow correctness track: OPEN — do not use -P 2+ as upload KPI workaround")
	t.Log("probe: python docker/masque-perf-lab/_bench_tcp_parallel_upload.py")
	t.Log("symptom: concurrent upload flows do not sum; second flow starves or breaks")
	t.Log("KPI path: single-flow tcp_up only; browser/multi-app fairness is separate gate")
}
