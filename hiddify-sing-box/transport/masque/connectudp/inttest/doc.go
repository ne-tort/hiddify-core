// Package inttest holds CONNECT-UDP integration tests (W-UDP-4 PR3+).
//
// Smoke: H3/H2 CoreSession echo, split-payload, forbidden, H2 ICMP.
// Localize gates: echo KPI, synth localize (H2/H3 prod profile), docker paced/burst,
// link L1/L3, H3 harness direct dial, wire contract, interrupt/leak GATE.
// GATE synth KPI tests remain in transport/masque/ (connectudp_synth_kpi_test.go).
// Stability/parallel/h2-harness runners: connectudp_inttest_*_export.go.
//
// Run: go test ./transport/masque/connectudp/inttest/ -count=1
package inttest
