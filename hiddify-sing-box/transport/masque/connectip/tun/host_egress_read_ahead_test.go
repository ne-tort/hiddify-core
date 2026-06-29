//go:build upload_gate

package tun

import (
	"context"
	"testing"
	"time"
)

// TestGATEConnectIPUploadReadAheadBurstOverlap (GATE-UP-11) read-ahead overlaps slow syscall when kernel bursts.
func TestGATEConnectIPUploadReadAheadBurstOverlap(t *testing.T) {
	requireUpload524SubMsClock(t)
	seg := makeUpload524BulkSeg(t)
	feed := newHostSyscallBatchFeed(seg, 2, 15*time.Microsecond)
	w := &mockL3Writer{}
	w.retainNext.Store(true)

	sync := runHostKernelPumpMeter(t, feed.read, w, 400*time.Millisecond, upload524PumpHarnessOpts{Prod: true, NoObserver: true})
	feed2 := newHostSyscallBatchFeed(seg, 2, 15*time.Microsecond)
	w2 := &mockL3Writer{}
	w2.retainNext.Store(true)
	ahead := runHostKernelPumpMeter(t, WrapHostEgressReadAhead(t.Context(), feed2.read), w2, 400*time.Millisecond, upload524PumpHarnessOpts{Prod: true, NoObserver: true})

	if sync.Mbps < 700 {
		t.Fatalf("sync batch-2x mbps=%.1f want >=700", sync.Mbps)
	}
	if ahead.Mbps < sync.Mbps*0.9 {
		t.Fatalf("read-ahead mbps=%.1f want >= 90%% of sync %.1f", ahead.Mbps, sync.Mbps)
	}
	t.Logf("read-ahead burst: sync=%.1f ahead=%.1f Mbps pkts/flush sync=%.2f ahead=%.2f",
		sync.Mbps, ahead.Mbps, sync.PktsPerFlush, ahead.PktsPerFlush)
}

// TestGATEConnectIPUploadReadAheadSyscallOverlap (GATE-UP-12) overlaps 10µs read syscall with 10µs wire write.
func TestGATEConnectIPUploadReadAheadSyscallOverlap(t *testing.T) {
	requireUpload524SubMsClock(t)
	seg := makeUpload524BulkSeg(t)
	const work = 10 * time.Microsecond
	harness := upload524PumpHarnessOpts{Prod: true, NoObserver: true}

	wSync := &mockL3Writer{}
	wSync.retainNext.Store(true)
	wSync.inPlaceDelay = work
	hostSync, cancelSync := hostEgressDepth1WithReadWork(seg, work)
	defer cancelSync()
	syncM := runHostKernelPumpMeter(t, hostSync, wSync, 500*time.Millisecond, harness)

	wAhead := &mockL3Writer{}
	wAhead.retainNext.Store(true)
	wAhead.inPlaceDelay = work
	hostAhead, cancelAhead := hostEgressDepth1WithReadWork(seg, work)
	defer cancelAhead()
	raCtx, raCancel := context.WithCancel(t.Context())
	defer raCancel()
	aheadM := runHostKernelPumpMeter(t, WrapHostEgressReadAhead(raCtx, hostAhead), wAhead, 500*time.Millisecond, harness)

	if syncM.Mbps > Upload524MbpsBandHi {
		t.Logf("sync already above 524 band: %.1f Mbps", syncM.Mbps)
	}
	if aheadM.Mbps < UploadDODMbps*0.75 {
		t.Fatalf("read-ahead overlap mbps=%.1f want >= %.0f (sync=%.1f)", aheadM.Mbps, UploadDODMbps*0.75, syncM.Mbps)
	}
	if aheadM.Mbps < syncM.Mbps*1.2 {
		t.Fatalf("read-ahead overlap mbps=%.1f want >= 1.2× sync %.1f", aheadM.Mbps, syncM.Mbps)
	}
	t.Logf("read-ahead overlap: sync=%.1f ahead=%.1f Mbps (read+write each %v)", syncM.Mbps, aheadM.Mbps, work)
}
