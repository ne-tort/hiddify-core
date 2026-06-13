package connectip

import "sync/atomic"

// OutboundQueueDepthLimit is the bounded depth of the client netstack outboundCh.
const OutboundQueueDepthLimit = netstackOutboundQueueDepth

// OutboundQueueMetrics tracks client outboundCh occupancy (optional test/profiling hook).
type OutboundQueueMetrics struct {
	Depth     atomic.Uint64
	DepthHigh atomic.Uint64
}

func (m *OutboundQueueMetrics) noteEnqueued() {
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

func (m *OutboundQueueMetrics) noteDequeued() {
	if m == nil {
		return
	}
	m.Depth.Add(^uint64(0))
}
