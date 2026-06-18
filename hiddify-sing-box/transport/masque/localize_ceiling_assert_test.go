package masque

import "testing"

// assertLocalizeStrictL256Ceiling35ms checks wire-FC ceiling repro (~60 Mbit/s @ L256+35ms RTT).
// Synth/Docker KPI ≥1000 Mbit/s uses prod path without strict L256 harness (TestGATE* / @0ms Docker).
func assertLocalizeStrictL256Ceiling35ms(t *testing.T, label string, mbps float64) {
	t.Helper()
	t.Logf("%s: %.1f Mbit/s (ceiling band [%.0f,%.0f]; AGENTS KPI %.0f+ without harness)",
		label, mbps, connectStreamStrictL256CeilingBandMbps, connectStreamStrictL256Ceiling35msMbps,
		connectStreamSynthProdMinMbps)
	if mbps < connectStreamStrictL256CeilingBandMbps {
		t.Fatalf("%s %.1f < %.0f Mbit/s (L256/35ms ceiling band broken)", label, mbps, connectStreamStrictL256CeilingBandMbps)
	}
	if mbps > connectStreamStrictL256Ceiling35msMbps+5 {
		t.Fatalf("%s %.1f > %.0f Mbit/s (unexpected above L256/35ms ceiling)", label, mbps, connectStreamStrictL256Ceiling35msMbps+5)
	}
}

// assertLocalizeDocker35msSequentialLeg reproduces Docker perf-lab @35ms sequential iperf (не DoD 1000+).
func assertLocalizeDocker35msSequentialLeg(t *testing.T, leg string, mbps, floorMbps float64) {
	t.Helper()
	t.Logf("docker-35ms-seq %s: %.1f Mbit/s (repro floor %.0f from perf-lab; DoD 1000+ только Docker @0ms)",
		leg, mbps, floorMbps)
	if mbps < floorMbps {
		t.Fatalf("%s %.1f < %.0f Mbit/s — synth не воспроизводит Docker @35ms; добавить/уточнить localize перед фиксом",
			leg, mbps, floorMbps)
	}
}
