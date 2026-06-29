//go:build upload_gate

package tun

import (
	"testing"
	"time"
)

// TestGATEConnectIPUploadBatchPumpAt524Pace (GATE-UP-16) RunTunnelBatch end-to-end @ 2 MSS/syscall @ 20µs.
func TestGATEConnectIPUploadBatchPumpAt524Pace(t *testing.T) {
	requireUpload524SubMsClock(t)
	seg := makeUpload524BulkSeg(t)
	feed := newHostSyscallBatchFeed(seg, 2, Upload524IterBudget)
	w := &mockL3Writer{}
	w.retainNext.Store(true)
	m := runHostKernelBatchPumpMeter(t, feed.read, w, 600*time.Millisecond)
	if m.Writes < 4000 {
		t.Fatalf("writes=%d want >=4000", m.Writes)
	}
	if m.PktsPerFlush < 1.8 {
		t.Fatalf("batch-pump pkts/flush=%.2f want >=1.8", m.PktsPerFlush)
	}
	if m.LoopIn.PktsPerIter < 1.8 {
		t.Fatalf("batch-pump pkts/iter=%.2f want >=1.8", m.LoopIn.PktsPerIter)
	}
	if m.Mbps < UploadDODMbps*0.85 {
		t.Fatalf("batch-pump: mbps=%.1f want >= %.0f (pps=%.0f pkts/flush=%.2f pkts/iter=%.2f)",
			m.Mbps, UploadDODMbps*0.85, m.PPS, m.PktsPerFlush, m.LoopIn.PktsPerIter)
	}
	t.Logf("batch-pump@20us: mbps=%.1f pkts/flush=%.2f pkts/iter=%.2f flushes/writes=%.2f",
		m.Mbps, m.PktsPerFlush, m.LoopIn.PktsPerIter, float64(m.Flushes)/float64(m.Writes))
}

// TestGATEConnectIPUploadBatchPumpDepth1Regression (GATE-UP-16b) depth-1 feed stays ~524 via batch path.
func TestGATEConnectIPUploadBatchPumpDepth1Regression(t *testing.T) {
	requireUpload524SubMsClock(t)
	seg := makeUpload524BulkSeg(t)
	host, cancel := hostEgressDepth1WithReadWork(seg, Upload524IterBudget)
	defer cancel()
	w := &mockL3Writer{}
	w.retainNext.Store(true)
	m := runHostKernelBatchPumpMeter(t, host, w, 600*time.Millisecond)
	assertUpload524Band(t, "batch-depth1", m)
	if m.LoopIn.PktsPerIter > 1.2 {
		t.Fatalf("depth-1 batch pkts/iter=%.2f want <=1.2", m.LoopIn.PktsPerIter)
	}
}

// TestGATEConnectIPUploadRunPumpBatchAt524Pace (GATE-UP-17) prod RunPump → RunTunnelBatch @ 2 MSS/syscall @ 20µs.
func TestGATEConnectIPUploadRunPumpBatchAt524Pace(t *testing.T) {
	requireUpload524SubMsClock(t)
	seg := makeUpload524BulkSeg(t)
	feed := newHostSyscallBatchFeed(seg, 2, Upload524IterBudget)
	w := &mockL3Writer{}
	w.retainNext.Store(true)
	m := runHostKernelRunPumpMeter(t, feed.read, w, 600*time.Millisecond)
	if m.Writes < 4000 {
		t.Fatalf("runpump writes=%d want >=4000", m.Writes)
	}
	if m.PktsPerFlush < 1.8 {
		t.Fatalf("runpump pkts/flush=%.2f want >=1.8", m.PktsPerFlush)
	}
	if m.Mbps < UploadDODMbps*0.85 {
		t.Fatalf("runpump: mbps=%.1f want >= %.0f (pps=%.0f pkts/flush=%.2f)",
			m.Mbps, UploadDODMbps*0.85, m.PPS, m.PktsPerFlush)
	}
	t.Logf("runpump-batch@20us: mbps=%.1f pkts/flush=%.2f flushes/writes=%.2f",
		m.Mbps, m.PktsPerFlush, float64(m.Flushes)/float64(m.Writes))
}
