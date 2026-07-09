package h3

import (
	"testing"
	"time"
)

// TestGATEH3SplitLegsWindowedBenchSynth (P4 synth): split_legs opt-in matches single_bidi windowed floor.
func TestGATEH3SplitLegsWindowedBenchSynth(t *testing.T) {
	single := benchWindowedProdTunnelConnMbps(35*time.Millisecond, TunnelWriteToBufLen)
	SetTestConnectStreamMode(ConnectStreamModeSplitLegs)
	defer ClearTestConnectStreamMode()
	if !ConnectStreamUsesSplitLegs() {
		t.Fatal("split_legs test hook not active")
	}
	// DualTunnelConn synth uses same per-leg TunnelConn benches; windowed floor must hold.
	dl := newRefBenchInfiniteStream()
	ul := newRefBenchInfiniteStream()
	dual := NewDualTunnelConn(DualTunnelConnParams{
		Download: NewTunnelConn(TunnelConnParams{H3Stream: dl}),
		Upload:   NewTunnelConn(TunnelConnParams{H3Stream: ul}),
	})
	sink := newBenchWindowedSink(35*time.Millisecond, TunnelWriteToBufLen, benchWindowedDuration)
	n, _ := dual.WriteTo(sink)
	splitMbps := float64(n*8) / benchWindowedDuration.Seconds() / 1e6
	t.Logf("single_bidi=%.1f split_legs=%.1f Mbit/s", single, splitMbps)
	const minMbps = 50.0
	if single < minMbps {
		t.Fatalf("single_bidi %.1f want >= %.0f", single, minMbps)
	}
	if splitMbps < minMbps*0.85 {
		t.Fatalf("split_legs %.1f want >= %.0f (85%% of single)", splitMbps, minMbps*0.85)
	}
}
