// Package inttest holds CONNECT-IP integration tests (W-IP-0 PR1+).

//

// Smoke/GATE: native H3/H2 in-proc servers (harness.go, harness_h2.go), synth gates,
// upload synth/localize. H2 dual-flow + short-FIN: P1-9 (multi_short_bulk_gate / dual_flow_gate).
// Sequential TCP connect/close churn: P2-12 (tcp_churn_gate).
// Mid-session multiflow recycle restore: P2-13 (mid_session_multiflow_recycle_gate).
// Mixed TCP+UDP many-flow: P3-3 (mixed_tcp_udp_gate).
// Benign plane half-close under multi-flow: P3-4 (benign_halfclose_multiflow_gate).

// upload synth (upload_synth_gate.go), upload localize (native_upload_localize.go).

// Localize/forwarder benches: gate runners in transport/masque + connectip_inttest_*_export.go.

//

// Harness lives in this package (not transport/masque) to avoid masque ↔ server import cycle.

//

// Run default smoke: go test ./transport/masque/connectip/inttest/ -count=1 -timeout 120s
// Heavy KPI benches: go test -tags masque_inttest_heavy ./transport/masque/connectip/inttest/ -timeout 600s

package inttest

