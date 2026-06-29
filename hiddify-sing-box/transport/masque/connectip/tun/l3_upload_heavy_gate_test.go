//go:build !upload_gate

package tun

import (
	"testing"
	"time"
)

// TestGATEConnectIPUpload524DiscriminateFastPath (LOCALIZE-UP-3) no throttle → must exceed 524 band (not tun-limited).
func TestGATEConnectIPUpload524DiscriminateFastPath(t *testing.T) {
	seg := makeUpload524BulkSeg(t)
	w := &mockL3Writer{}
	m := runHostKernelPumpMeter(t, hostEgressInfinite(seg), w, 150*time.Millisecond, upload524PumpHarnessOpts{
		LoopInUsqueImmediate: true,
	})
	if m.Writes < 500 {
		t.Fatalf("writes=%d want >=500", m.Writes)
	}
	if m.Mbps <= Upload524MbpsBandHi {
		t.Fatalf("fast path mbps=%.1f want > %.0f (proves 524 is throttle identity, not mock ceiling)",
			m.Mbps, Upload524MbpsBandHi)
	}
	if m.PPS <= float64(Upload524PPSBandHi) {
		t.Fatalf("fast path pps=%.0f want > %d", m.PPS, Upload524PPSBandHi)
	}
	t.Logf("fast path: writes=%d pps=%.0f mbps=%.1f pkts/flush=%.1f",
		m.Writes, m.PPS, m.Mbps, m.PktsPerFlush)
}

// TestGATEConnectIPUpload524CauseSummary logs the localization verdict (always pass — diagnostic gate).
func TestGATEConnectIPUpload524CauseSummary(t *testing.T) {
	got := upload524MbpsFromPPS(Upload524PPS, Upload524SegBytes)
	if got < Upload524MbpsBandLo || got > Upload524MbpsBandHi {
		t.Fatalf("formula mbps=%.1f want band", got)
	}
	t.Logf("LOCALIZE verdict: Docker 524 = %d pps × %d B = %.1f Mbit/s",
		Upload524PPS, Upload524SegBytes, got)
	t.Logf("LOCALIZE repro: pace host OR wire @ %v → same band (LOCALIZE-UP-1/2)", Upload524PktSpacing)
	t.Logf("LOCALIZE discriminate: unpaced pump >>524 (LOCALIZE-UP-3) → prod cap = iteration budget @ ~50 kpps")
	t.Logf("LOCALIZE prod mapping: kernel tun ReadHostEgress depth-1 ≈ %v/pkt (not slow QUIC on instant wire)", Upload524PktSpacing)
}

// TestGATEConnectIPUploadDepth1ImmediateCeiling (GATE-UP-10) no artificial read work → must exceed 524 band (userspace headroom).
func TestGATEConnectIPUploadDepth1ImmediateCeiling(t *testing.T) {
	seg := makeUpload524BulkSeg(t)
	host, cancel := hostEgressDepth1Immediate(seg)
	defer cancel()
	w := &mockL3Writer{}
	w.retainNext.Store(true)
	m := runHostKernelPumpMeter(t, host, w, 200*time.Millisecond, upload524PumpHarnessOpts{Prod: true, NoObserver: true})
	if m.Writes < 500 {
		t.Fatalf("writes=%d want >=500", m.Writes)
	}
	if m.Mbps <= Upload524MbpsBandHi {
		t.Fatalf("depth-1 immediate mbps=%.1f want > %.0f (userspace not 524-capped)", m.Mbps, Upload524MbpsBandHi)
	}
	logUploadBoundMetrics(t, "depth-1-immediate", m)
}
