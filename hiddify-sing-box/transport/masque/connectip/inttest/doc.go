// Package inttest holds CONNECT-IP integration tests (W-IP-0 PR1+).
//
// Smoke: hybrid connect_ip + connect_stream H3/H2 echo + download sanity (harness.go).
// GATE synth: native H3 (native_synth_gate.go), hybrid download KPI (hybrid_kpi_gate.go),
// upload synth (upload_synth_gate.go), upload localize (native_upload_localize.go).
// Localize/forwarder benches: gate runners in transport/masque + connectip_inttest_*_export.go.
//
// Harness lives in this package (not transport/masque) to avoid masque ↔ server import cycle.
//
// Run: go test ./transport/masque/connectip/inttest/ -count=1
package inttest
