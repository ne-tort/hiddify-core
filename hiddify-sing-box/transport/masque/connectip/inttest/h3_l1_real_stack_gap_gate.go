//go:build masque_inttest_heavy

package inttest

// P6-H3-REAL-STACK-GAP: synth ReadPacket @ MSS vs real H3 L1 TCP.

import (
	"testing"
)

const (
	h3RealStackGapBenchDur       = NativeSynthBenchDur
	h3RealStackGapMinBytes       = 4 * 1024 * 1024
	h3RealStackGapSynthIP512     = 540
	h3RealStackGapSynthIPMSS     = 1500
	h3RealStackGapSynthRealMin   = 1.00
	h3RealStackGapSynthScaleMin  = 1.15
	h3RealStackGapTCPBandFloor   = h3PerfDownFloor
	h3RealStackGapTCPBandCeiling = h3PerfDownCeiling
	h3RealStackGapByteNsPerBMin  = 3.0
	h3RealStackGapByteNsPerBMax  = 20.0
)

// RunGATEConnectIPH3RealStackGapAtMSS proves real L1 H3 meets band at MSS with synth still ≥ real.
func RunGATEConnectIPH3RealStackGapAtMSS(t *testing.T) {
	t.Helper()
	synth512 := runSyntheticH2ReadPacketSample(t, h3RealStackGapSynthIP512, h3RealStackGapBenchDur)
	synthMSS := runSyntheticH2ReadPacketSample(t, h3RealStackGapSynthIPMSS, h3RealStackGapBenchDur)

	stack := openConnectIPH3L1Pipe(t)
	tcp := runL1DownloadSample(t, stack, "l1-h3", h3RealStackGapBenchDur)

	logAndAnalyzeH3RealStackGap(t, synth512, synthMSS, tcp)
}

func logAndAnalyzeH3RealStackGap(t *testing.T, synth512, synthMSS, tcp ThroughputSample) {
	t.Helper()
	t.Logf("REAL-STACK-H3 synth512 %s", synth512)
	t.Logf("REAL-STACK-H3 synthMSS %s", synthMSS)
	t.Logf("REAL-STACK-H3 tcp %s", tcp)

	if tcp.Bytes < h3RealStackGapMinBytes {
		t.Fatalf("L1 H3 TCP bytes=%d want>=%d", tcp.Bytes, h3RealStackGapMinBytes)
	}
	if tcp.Mbps < h3RealStackGapTCPBandFloor || tcp.Mbps > h3RealStackGapTCPBandCeiling {
		t.Fatalf("L1 H3 TCP %.1f outside band [%.0f, %.0f]", tcp.Mbps, h3RealStackGapTCPBandFloor, h3RealStackGapTCPBandCeiling)
	}
	if tcp.NsPerByte < h3RealStackGapByteNsPerBMin || tcp.NsPerByte > h3RealStackGapByteNsPerBMax {
		t.Fatalf("L1 H3 ns/B=%.1f outside band [%.0f, %.0f]", tcp.NsPerByte, h3RealStackGapByteNsPerBMin, h3RealStackGapByteNsPerBMax)
	}

	synthRealMSS := synthMSS.Mbps / tcp.Mbps
	synthScale := synthMSS.Mbps / synth512.Mbps
	t.Logf("REAL-STACK-H3 synthMSS/realTCP=%.2f synthMSS/synth512=%.2f", synthRealMSS, synthScale)

	if synthRealMSS < h3RealStackGapSynthRealMin {
		t.Fatalf("synthMSS/realTCP %.2f < %.2f — H3 real stack gap missing (harness/regression)",
			synthRealMSS, h3RealStackGapSynthRealMin)
	}
	if synthScale < h3RealStackGapSynthScaleMin {
		t.Fatalf("synthMSS/synth512 %.2f < %.2f — in-memory pipe should scale", synthScale, h3RealStackGapSynthScaleMin)
	}
	t.Logf("REAL-STACK-H3 PASS: real H3 ~%.0f Mbit/s at MSS (synthMSS/real=%.2f)", tcp.Mbps, synthRealMSS)
}
