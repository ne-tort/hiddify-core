//go:build masque_inttest_heavy

package inttest

// P6-D1-H2-BIDI: localize H2 download ceiling vs concurrent C2S upload on same L1 plane.

import (
	"testing"
)

const (
	l1BidiBenchDur           = NativeSynthBenchDur
	l1BidiMinBytes           = 8 * 1024 * 1024
	l1BidiContentionMinRatio = 0.75 // duplex/alone below => bulk upload kills download
	l1BidiH2AloneBandFloor   = h2PerfDownFloor
	l1BidiH2AloneBandCeiling = h2PerfDownCeiling
)

type l1BidiLeg struct {
	Alone  ThroughputSample
	Duplex ThroughputSample
}

// RunGATEConnectIPH2L1BidiContention compares download-only vs download+upload on L1 H2 and H3.
func RunGATEConnectIPH2L1BidiContention(t *testing.T) {
	t.Helper()
	h2 := measureL1BidiLeg(t, "l1-h2", openConnectIPH2L1Pipe)
	h3 := measureL1BidiLeg(t, "l1-h3", openConnectIPH3L1Pipe)
	logAndAnalyzeL1Bidi(t, h2, h3)
}

func measureL1BidiLeg(t *testing.T, layer string, open func(testing.TB) *connectIPL1Stack) l1BidiLeg {
	t.Helper()
	aloneStack := open(t)
	alone := runL1DownloadSample(t, aloneStack, layer, l1BidiBenchDur)

	duplexStack := open(t)
	duplex := runL1DuplexDownloadSample(t, duplexStack, layer, l1BidiBenchDur)
	return l1BidiLeg{Alone: alone, Duplex: duplex}
}

func logAndAnalyzeL1Bidi(t *testing.T, h2, h3 l1BidiLeg) {
	t.Helper()
	logL1BidiLeg(t, "h2", h2)
	logL1BidiLeg(t, "h3", h3)

	if h2.Alone.Bytes < l1BidiMinBytes {
		t.Fatalf("H2 alone bytes=%d want>=%d", h2.Alone.Bytes, l1BidiMinBytes)
	}
	if h2.Alone.Mbps < l1BidiH2AloneBandFloor || h2.Alone.Mbps > l1BidiH2AloneBandCeiling {
		t.Fatalf("H2 alone download %.1f outside band [%.0f, %.0f]",
			h2.Alone.Mbps, l1BidiH2AloneBandFloor, l1BidiH2AloneBandCeiling)
	}

	h2Ratio := h2.Duplex.Mbps / h2.Alone.Mbps
	h3Ratio := safeMbpsRatio(h3.Duplex.Mbps, h3.Alone.Mbps)

	if h2Ratio < l1BidiContentionMinRatio {
		t.Fatalf("H2 duplex contends with download: ratio=%.2f (alone=%.1f duplex=%.1f) — bidi tax explains ceiling",
			h2Ratio, h2.Alone.Mbps, h2.Duplex.Mbps)
	}

	t.Logf("BIDI PASS: H2 download ceiling not bulk-bidi limited (duplex/alone=%.2f alone=%.1f duplex=%.1f)",
		h2Ratio, h2.Alone.Mbps, h2.Duplex.Mbps)
	if h3Ratio < l1BidiContentionMinRatio && h3.Duplex.Bytes >= l1BidiMinBytes/4 {
		t.Logf("OPEN: H3 L1 duplex collapses download (ratio=%.2f) while H2 stable — QUIC/shared-path asymmetry",
			h3Ratio)
	}
}

func logL1BidiLeg(t *testing.T, name string, leg l1BidiLeg) {
	t.Helper()
	t.Logf("BIDI %s alone: %s", name, leg.Alone)
	t.Logf("BIDI %s duplex: %s", name, leg.Duplex)
	ratio := safeMbpsRatio(leg.Duplex.Mbps, leg.Alone.Mbps)
	t.Logf("BIDI %s duplex/alone download ratio=%.2f (alone=%.1f duplex=%.1f Mbit/s)",
		name, ratio, leg.Alone.Mbps, leg.Duplex.Mbps)
	if ratio < l1BidiContentionMinRatio {
		t.Logf("OPEN: %s concurrent upload contends with download (ratio %.2f < %.2f)",
			name, ratio, l1BidiContentionMinRatio)
	}
}

func safeMbpsRatio(num, den float64) float64 {
	if den <= 0 {
		return 0
	}
	return num / den
}
