package monitoring

import (
	"context"
	"testing"
	"time"
)

func TestDeactivateCancelsProbeContext(t *testing.T) {
	parent := context.Background()
	probeCtx, cancel := context.WithCancel(parent)
	m := &OutboundMonitoring{
		ctx:    probeCtx,
		cancel: cancel,
	}
	active.Store(m)
	Deactivate()
	select {
	case <-probeCtx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("Deactivate must cancel monitor probe ctx")
	}
	if active.Load() != nil {
		t.Fatal("active monitor should be cleared")
	}
}

func TestMergeProbeParentCancelsOnCaller(t *testing.T) {
	monitor, mCancel := context.WithCancel(context.Background())
	defer mCancel()
	caller, cCancel := context.WithCancel(context.Background())
	ctx, cancel := mergeProbeParent(monitor, caller)
	defer cancel()
	cCancel()
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("merged ctx should cancel when caller cancels")
	}
}

func TestMergeProbeParentCancelsOnMonitor(t *testing.T) {
	monitor, mCancel := context.WithCancel(context.Background())
	caller := context.Background()
	ctx, cancel := mergeProbeParent(monitor, caller)
	defer cancel()
	mCancel()
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("merged ctx should cancel when monitor cancels")
	}
}

func TestDeactivateWaitsForInFlight(t *testing.T) {
	probeCtx, cancel := context.WithCancel(context.Background())
	m := &OutboundMonitoring{
		ctx:    probeCtx,
		cancel: cancel,
	}
	m.probesInFlight.Add(1)
	active.Store(m)

	released := make(chan struct{})
	go func() {
		time.Sleep(30 * time.Millisecond)
		m.probesInFlight.Done()
		close(released)
	}()

	start := time.Now()
	Deactivate()
	elapsed := time.Since(start)
	select {
	case <-released:
	default:
		t.Fatal("Deactivate returned before in-flight Done")
	}
	if elapsed < 20*time.Millisecond {
		t.Fatalf("Deactivate returned too fast (%v); expected wait for probes", elapsed)
	}
}
