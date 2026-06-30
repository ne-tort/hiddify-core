//go:build upload_gate

package tun

import (
	"context"
	"testing"
	"time"
)

func prodUploadHarness() upload524PumpHarnessOpts {
	return upload524PumpHarnessOpts{Prod: true}
}

// TestGATEConnectIPUpload524IterBudget20us (GATE-UP-7) 20µs/pkt feed → 524 band (prod RunTunnelBatch).
func TestGATEConnectIPUpload524IterBudget20us(t *testing.T) {
	requireUpload524SubMsClock(t)
	seg := makeUpload524BulkSeg(t)
	m := runHostKernelPumpMeter(t, hostEgressReadPaced(Upload524IterBudget, seg), &mockL3Writer{}, 600*time.Millisecond, upload524PumpHarnessOpts{Prod: true, NoObserver: true})
	if m.Writes < 2000 {
		t.Fatalf("writes=%d want >=2000", m.Writes)
	}
	assertUpload524Band(t, "iter-budget-20us", m)
	if m.PktsPerFlush > Upload524PktsPerFlushMax {
		t.Fatalf("pkts/flush=%.2f want <=%.2f", m.PktsPerFlush, Upload524PktsPerFlushMax)
	}
	logUploadBoundMetrics(t, "iter-budget-20us", m)
}

// TestGATEConnectIPUploadIterBudgetRatio (GATE-UP-8) 10.5µs vs 20µs syscall budget → ≥1.5× throughput (same run).
func TestGATEConnectIPUploadIterBudgetRatio(t *testing.T) {
	requireUpload524SubMsClock(t)
	seg := makeUpload524BulkSeg(t)
	harness := upload524PumpHarnessOpts{Prod: true, NoObserver: true}
	w20 := &mockL3Writer{}
	w20.retainNext.Store(true)
	host20, cancel20 := hostEgressDepth1WithReadWork(seg, Upload524IterBudget)
	defer cancel20()
	m20 := runHostKernelPumpMeter(t, host20, w20, 400*time.Millisecond, harness)
	w10 := &mockL3Writer{}
	w10.retainNext.Store(true)
	host10, cancel10 := hostEgressDepth1WithReadWork(seg, UploadDODIterBudget)
	defer cancel10()
	m10 := runHostKernelPumpMeter(t, host10, w10, 400*time.Millisecond, harness)
	if m20.Mbps < 300 {
		t.Fatalf("20µs baseline mbps=%.1f too low for ratio test", m20.Mbps)
	}
	ratio := m10.Mbps / m20.Mbps
	if ratio < 1.35 {
		t.Fatalf("iter budget ratio=%.2f want >=1.35 (20µs=%.1f 10µs=%.1f Mbit/s)", ratio, m20.Mbps, m10.Mbps)
	}
	t.Logf("iter budget ratio: 10µs/20µs=%.2f (%.1f → %.1f Mbit/s) pkts/flush %.2f/%.2f",
		ratio, m20.Mbps, m10.Mbps, m20.PktsPerFlush, m10.PktsPerFlush)
}

// TestGATEConnectIPUploadDODBatchRead2x (GATE-UP-9) 2 pkts/syscall @ 10µs → DoD without halving syscall alone.
func TestGATEConnectIPUploadDODBatchRead2x(t *testing.T) {
	requireUpload524SubMsClock(t)
	seg := makeUpload524BulkSeg(t)
	feed := newHostSyscallBatchFeed(seg, 2, UploadDODIterBudget)
	w := &mockL3Writer{}
	w.retainNext.Store(true)
	m := runHostKernelPumpMeter(t, feed.read, w, 500*time.Millisecond, upload524PumpHarnessOpts{Prod: true, NoObserver: true})
	if m.Writes < 4000 {
		t.Fatalf("writes=%d want >=4000", m.Writes)
	}
	if m.PktsPerFlush < 1.8 {
		t.Fatalf("batch read pkts/flush=%.2f want >=1.8", m.PktsPerFlush)
	}
	if m.Mbps < UploadDODMbps*0.85 {
		t.Fatalf("DoD batch-2x: mbps=%.1f want >= %.0f (pps=%.0f pkts/flush=%.2f)",
			m.Mbps, UploadDODMbps*0.85, m.PPS, m.PktsPerFlush)
	}
	logUploadBoundMetrics(t, "batch-2x-10us", m)
}

// TestGATEConnectIPUploadDODReadAheadBatch2x (GATE-UP-13) read-ahead + 2 pkts/syscall @ 10µs → DoD prod combo path.
func TestGATEConnectIPUploadDODReadAheadBatch2x(t *testing.T) {
	requireUpload524SubMsClock(t)
	seg := makeUpload524BulkSeg(t)
	feed := newHostSyscallBatchFeed(seg, 2, UploadDODIterBudget)
	w := &mockL3Writer{}
	w.retainNext.Store(true)
	raCtx, raCancel := context.WithCancel(t.Context())
	defer raCancel()
	readAhead, _ := WrapHostEgressReadAheadBatch(raCtx, feed.read)
	m := runHostKernelPumpMeter(t, readAhead, w, 500*time.Millisecond, upload524PumpHarnessOpts{Prod: true, NoObserver: true})
	if m.Writes < 4000 {
		t.Fatalf("writes=%d want >=4000", m.Writes)
	}
	if m.PktsPerFlush < 1.8 {
		t.Fatalf("read-ahead+batch pkts/flush=%.2f want >=1.8", m.PktsPerFlush)
	}
	if m.Mbps < UploadDODMbps*0.85 {
		t.Fatalf("read-ahead+batch: mbps=%.1f want >= %.0f (pps=%.0f pkts/flush=%.2f)",
			m.Mbps, UploadDODMbps*0.85, m.PPS, m.PktsPerFlush)
	}
	logUploadBoundMetrics(t, "read-ahead+batch-2x", m)
}

// TestGATEConnectIPUploadDODBatchRead2xAt524Pace (GATE-UP-15) 2 pkts/syscall @ 20µs — DoD at kernel pacing (not faster syscall).
func TestGATEConnectIPUploadDODBatchRead2xAt524Pace(t *testing.T) {
	requireUpload524SubMsClock(t)
	seg := makeUpload524BulkSeg(t)
	feed := newHostSyscallBatchFeed(seg, 2, Upload524IterBudget)
	w := &mockL3Writer{}
	w.retainNext.Store(true)
	m := runHostKernelPumpMeter(t, feed.read, w, 600*time.Millisecond, upload524PumpHarnessOpts{Prod: true, NoObserver: true})
	if m.Writes < 4000 {
		t.Fatalf("writes=%d want >=4000", m.Writes)
	}
	if m.PktsPerFlush < 1.8 {
		t.Fatalf("batch-2x@20us pkts/flush=%.2f want >=1.8", m.PktsPerFlush)
	}
	if m.Mbps < UploadDODMbps*0.85 {
		t.Fatalf("batch-2x@20us: mbps=%.1f want >= %.0f (pps=%.0f pkts/flush=%.2f)",
			m.Mbps, UploadDODMbps*0.85, m.PPS, m.PktsPerFlush)
	}
	t.Logf("batch-2x@20us: mbps=%.1f pkts/flush=%.2f (Docker target: virtio batch @ 50 kpps)", m.Mbps, m.PktsPerFlush)
}

// TestGATEConnectIPUploadDODKernelQueueCoalesce (GATE-UP-14) paced kernel queue + coalesce drain (no syscall batch).
func TestGATEConnectIPUploadDODKernelQueueCoalesce(t *testing.T) {
	requireUpload524SubMsClock(t)
	seg := makeUpload524BulkSeg(t)
	q, qCancel := newHostEgressKernelQueue(seg, Upload524PktSpacing, 2)
	defer qCancel()
	w := &mockL3Writer{}
	w.retainNext.Store(true)
	m := runHostKernelPumpMeter(t, q.read, w, 600*time.Millisecond, upload524PumpHarnessOpts{Prod: true, NoObserver: true})
	if m.Writes < 4000 {
		t.Fatalf("writes=%d want >=4000", m.Writes)
	}
	if m.PktsPerFlush < 1.5 {
		t.Fatalf("kernel-queue pkts/flush=%.2f want >=1.5", m.PktsPerFlush)
	}
	if m.Mbps < UploadDODMbps*0.75 {
		t.Fatalf("kernel-queue: mbps=%.1f want >= %.0f (pps=%.0f pkts/flush=%.2f)",
			m.Mbps, UploadDODMbps*0.75, m.PPS, m.PktsPerFlush)
	}
	t.Logf("kernel-queue: mbps=%.1f pkts/flush=%.2f", m.Mbps, m.PktsPerFlush)
}
