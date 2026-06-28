// Package inttest holds CONNECT-stream integration tests (W-STR-4 PR6).
//
// Moved: H2/H3 prod-stack, H2/H3 transport FC, H2/H3 socks smoke, H3 localize twin/L256,
// H2/H3 localize bench, H2 docker-localize synth.
// GATE tests remain in transport/masque/ (connect_stream_synth_kpi_*, TestGATEDocker*, TestGATEH3*).
// H3 wake/injector localize tests remain in transport/masque/connect_stream_localize_test.go.
//
// Run: go test ./transport/masque/stream/inttest/ -count=1
package inttest
