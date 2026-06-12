package forwarder

import "testing"

func TestWriteQueueMetricsHighWater(t *testing.T) {
	t.Parallel()
	var m WriteQueueMetrics
	for i := 0; i < 5; i++ {
		m.noteEnqueued()
	}
	if got := m.Depth.Load(); got != 5 {
		t.Fatalf("depth=%d want 5", got)
	}
	if got := m.DepthHigh.Load(); got != 5 {
		t.Fatalf("depthHigh=%d want 5", got)
	}
	m.noteDequeued()
	m.noteDequeued()
	if got := m.Depth.Load(); got != 3 {
		t.Fatalf("depth after dequeue=%d want 3", got)
	}
	if got := m.DepthHigh.Load(); got != 5 {
		t.Fatalf("depthHigh after dequeue=%d want 5", got)
	}
}
