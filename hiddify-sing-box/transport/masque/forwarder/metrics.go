package forwarder

import "sync/atomic"

// WriteQueueDepth is the bounded depth of the forwarder writeCh (server→client segments).
const WriteQueueDepth = writeQueueDepth

// WriteQueueMetrics tracks CONNECT-IP forwarder writeCh occupancy (optional test/profiling hook).
type WriteQueueMetrics struct {
	Depth     atomic.Uint64
	DepthHigh atomic.Uint64
}

func (m *WriteQueueMetrics) noteEnqueued() {
	if m == nil {
		return
	}
	depth := m.Depth.Add(1)
	for {
		high := m.DepthHigh.Load()
		if depth <= high || m.DepthHigh.CompareAndSwap(high, depth) {
			return
		}
	}
}

func (m *WriteQueueMetrics) noteDequeued() {
	if m == nil {
		return
	}
	m.Depth.Add(^uint64(0))
}
