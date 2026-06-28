package tun

import (
	"testing"
	"time"
)

func logUploadBoundMetrics(t *testing.T, label string, m upload524PumpMeter) {
	t.Helper()
	t.Logf("%s: bound=%s writes=%d flushes=%d pps=%.0f mbps=%.1f pkts/flush=%.2f pkts/iter=%.2f read_us/pkt=%.1f write_us/pkt=%.1f host_accepted=%d",
		label, m.Bound, m.Writes, m.Flushes, m.PPS, m.Mbps, m.PktsPerFlush,
		m.LoopIn.PktsPerIter, m.LoopIn.ReadUsPerPkt, m.LoopIn.WriteUsPerPkt, m.HostRead.Accepted)
}

// TestGATEConnectIPUploadBoundDiscriminator (GATE-UP-6) classifies read-bound vs flush-bound vs unpaced
// before any prod wiring change. Not a repeat of LOCALIZE-UP pacing-only gates.
func TestGATEConnectIPUploadBoundDiscriminator(t *testing.T) {
	seg := makeUpload524BulkSeg(t)

	// unpaced → neither bound, >>524 (runs on all platforms)
	unpaced := runHostKernelPumpMeter(t, hostEgressInfinite(seg), &mockL3Writer{}, 150*time.Millisecond, upload524PumpHarnessOpts{
		CoalescePoll:         0,
		LoopInUsqueImmediate: true,
	})
	logUploadBoundMetrics(t, "unpaced", unpaced)
	if unpaced.Bound != UploadBoundUnpaced {
		t.Fatalf("unpaced bound=%s want %s mbps=%.1f", unpaced.Bound, UploadBoundUnpaced, unpaced.Mbps)
	}
	if unpaced.Mbps <= Upload524MbpsBandHi {
		t.Fatalf("unpaced mbps=%.1f want > %.0f", unpaced.Mbps, Upload524MbpsBandHi)
	}

	requireUpload524SubMsClock(t)

	// host-paced @ 20µs → read_bound, ~524 band
	hostPaced := runHostKernelPumpMeter(t, hostEgressReadPaced(Upload524PktSpacing, seg), &mockL3Writer{}, 400*time.Millisecond, upload524PumpHarnessOpts{
		CoalescePoll:         0,
		LoopInUsqueImmediate: true,
	})
	logUploadBoundMetrics(t, "host-paced", hostPaced)
	if hostPaced.Bound != UploadBoundRead {
		t.Fatalf("host-paced bound=%s want %s (read_us=%.1f write_us=%.1f)",
			hostPaced.Bound, UploadBoundRead, hostPaced.LoopIn.ReadUsPerPkt, hostPaced.LoopIn.WriteUsPerPkt)
	}
	if hostPaced.PktsPerFlush > 2.5 {
		t.Fatalf("host-paced pkts/flush=%.2f want <=2.5 (depth-1 prod parity)", hostPaced.PktsPerFlush)
	}

	// wire-paced @ 20µs → flush_bound, ~524 band
	wirePacedW := &mockL3Writer{inPlaceDelay: Upload524PktSpacing}
	wirePaced := runHostKernelPumpMeter(t, hostEgressInfinite(seg), wirePacedW, 400*time.Millisecond, upload524PumpHarnessOpts{
		CoalescePoll:         0,
		LoopInUsqueImmediate: true,
	})
	logUploadBoundMetrics(t, "wire-paced", wirePaced)
	if wirePaced.Bound != UploadBoundFlush {
		t.Fatalf("wire-paced bound=%s want %s (read_us=%.1f write_us=%.1f)",
			wirePaced.Bound, UploadBoundFlush, wirePaced.LoopIn.ReadUsPerPkt, wirePaced.LoopIn.WriteUsPerPkt)
	}
}
