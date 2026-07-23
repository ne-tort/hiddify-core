//go:build upload_gate

package tun

import (
	"testing"
	"time"
)

// TestGATEConnectIPUpload524ReproHostPaced (LOCALIZE-UP-1) depth-1 host @ 20µs/pkt → 524 Mbit/s identity.
func TestGATEConnectIPUpload524ReproHostPaced(t *testing.T) {
	requireUpload524SubMsClock(t)
	seg := makeUpload524BulkSeg(t)
	w := &mockL3Writer{}
	m := runHostKernelPumpMeter(t, hostEgressReadPaced(Upload524PktSpacing, seg), w, 600*time.Millisecond, upload524PumpHarnessOpts{})
	if m.Writes < 2000 {
		t.Fatalf("writes=%d want >=2000 for steady sample", m.Writes)
	}
	assertUpload524Band(t, "host-paced", m)
}

// TestGATEConnectIPUpload524ReproWirePaced (LOCALIZE-UP-2) instant host + 20µs wire → same 524 band.
func TestGATEConnectIPUpload524ReproWirePaced(t *testing.T) {
	requireUpload524SubMsClock(t)
	seg := makeUpload524BulkSeg(t)
	w := &mockL3Writer{inPlaceDelay: Upload524PktSpacing}
	m := runHostKernelPumpMeter(t, hostEgressInfinite(seg), w, 600*time.Millisecond, upload524PumpHarnessOpts{})
	if m.Writes < 2000 {
		t.Fatalf("writes=%d want >=2000", m.Writes)
	}
	assertUpload524Band(t, "wire-paced", m)
}

// TestGATEConnectIPUploadBoundDiscriminatorPaced (GATE-UP-6b) host/wire @ 20µs → read_bound / flush_bound.
func TestGATEConnectIPUploadBoundDiscriminatorPaced(t *testing.T) {
	requireUpload524SubMsClock(t)
	seg := makeUpload524BulkSeg(t)

	hostPaced := runHostKernelPumpMeter(t, hostEgressReadPaced(Upload524PktSpacing, seg), &mockL3Writer{}, 400*time.Millisecond, upload524PumpHarnessOpts{})
	logUploadBoundMetrics(t, "host-paced", hostPaced)
	if hostPaced.Bound != UploadBoundRead {
		t.Fatalf("host-paced bound=%s want %s (read_us=%.1f write_us=%.1f)",
			hostPaced.Bound, UploadBoundRead, hostPaced.LoopIn.ReadUsPerPkt, hostPaced.LoopIn.WriteUsPerPkt)
	}
	if hostPaced.PktsPerFlush > 2.5 {
		t.Fatalf("host-paced pkts/flush=%.2f want <=2.5 (depth-1 prod parity)", hostPaced.PktsPerFlush)
	}

	wirePacedW := &mockL3Writer{inPlaceDelay: Upload524PktSpacing}
	wirePaced := runHostKernelPumpMeter(t, hostEgressInfinite(seg), wirePacedW, 400*time.Millisecond, upload524PumpHarnessOpts{})
	logUploadBoundMetrics(t, "wire-paced", wirePaced)
	if wirePaced.Bound != UploadBoundFlush {
		t.Fatalf("wire-paced bound=%s want %s (read_us=%.1f write_us=%.1f)",
			wirePaced.Bound, UploadBoundFlush, wirePaced.LoopIn.ReadUsPerPkt, wirePaced.LoopIn.WriteUsPerPkt)
	}
}
