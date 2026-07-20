//go:build masque_inttest_heavy

package inttest

// P6-D1-H2-H3-L1-PARITY: structural H2/H3 gap on the same L1 netstack (no coreSession/TUN).

import (
	"testing"

	"github.com/sagernet/sing-box/transport/masque"
)

const (
	l1ParityBenchDur         = NativeSynthBenchDur
	l1ParityMinBytes         = 8 * 1024 * 1024
	l1ParityH2DownBandFloor  = 250.0
	l1ParityH2DownBandCeiling = 420.0
	l1ParityH3DownFloor      = 700.0
	l1ParityMaxH2H3DownRatio = 0.55 // structural gap on identical netstack/ingress
)

// RunGATEConnectIPH2H3L1Parity measures H2 vs H3 download on minimal L1 pipe (same gVisor netstack path).
func RunGATEConnectIPH2H3L1Parity(t *testing.T) {
	t.Helper()
	h2Stack := openConnectIPH2L1Pipe(t)
	h2 := runL1DownloadSample(t, h2Stack, "l1-h2", l1ParityBenchDur)

	h3Stack := openConnectIPH3L1Pipe(t)
	h3 := runL1DownloadSample(t, h3Stack, "l1-h3", l1ParityBenchDur)

	logAndAnalyzeL1Parity(t, h2, h3)
}

func logAndAnalyzeL1Parity(t *testing.T, h2, h3 ThroughputSample) {
	t.Helper()
	t.Logf("L1-PARITY %s", h2)
	t.Logf("L1-PARITY %s", h3)

	if h2.Bytes < l1ParityMinBytes || h3.Bytes < l1ParityMinBytes {
		t.Fatalf("L1 parity bytes too small: h2=%d h3=%d want>=%d", h2.Bytes, h3.Bytes, l1ParityMinBytes)
	}

	if h2.Mbps < l1ParityH2DownBandFloor || h2.Mbps > l1ParityH2DownBandCeiling {
		t.Fatalf("L1 H2 download %.1f outside band [%.0f, %.0f]", h2.Mbps, l1ParityH2DownBandFloor, l1ParityH2DownBandCeiling)
	}
	if h3.Mbps < l1ParityH3DownFloor {
		t.Logf("WARN: L1 H3 download %.1f below floor %.0f — host variance", h3.Mbps, l1ParityH3DownFloor)
	}

	ratio := h2.Mbps / h3.Mbps
	t.Logf("L1-PARITY H2/H3 download ratio=%.2f (H2=%.1f H3=%.1f Mbit/s)", ratio, h2.Mbps, h3.Mbps)

	if ratio > l1ParityMaxH2H3DownRatio {
		t.Fatalf("L1 H2/H3 ratio %.2f > %.2f — structural gap missing on minimal stack (regression?)",
			ratio, l1ParityMaxH2H3DownRatio)
	}

	for _, s := range []ThroughputSample{h2, h3} {
		t.Logf("L1-PARITY %s ns/B=%.1f cpu_ceil=%.0f observed=%.1f",
			s.Layer, s.NsPerByte, masque.SynthCPUMbpsCeiling(s.NsPerByte), s.Mbps)
	}
	t.Logf("L1-PARITY PASS: structural H2 download gap on wire layer (ratio=%.2f, H2≈%.0f H3≈%.0f)",
		ratio, h2.Mbps, h3.Mbps)
}
