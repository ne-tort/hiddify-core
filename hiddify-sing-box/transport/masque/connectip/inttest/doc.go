// Package inttest holds CONNECT-IP integration tests (W-IP-0 PR1+).

//

// Smoke/GATE: native H3 in-proc server (harness.go), synth gates (native_synth_gate.go),

// upload synth (upload_synth_gate.go), upload localize (native_upload_localize.go).

// Localize/forwarder benches: gate runners in transport/masque + connectip_inttest_*_export.go.

//

// Harness lives in this package (not transport/masque) to avoid masque ↔ server import cycle.

//

// Run: go test ./transport/masque/connectip/inttest/ -count=1

package inttest

