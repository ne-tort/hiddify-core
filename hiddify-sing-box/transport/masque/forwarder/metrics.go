package forwarder

import "sync/atomic"

// WriteQueueDepth is the bounded depth of the forwarder writeCh (server→client segments).
const WriteQueueDepth = writeQueueDepth

// DownloadQueueDepth is the bounded depth of the forwarder downloadCh (remote→client DATA).
const DownloadQueueDepth = downloadQueueDepth

type queueDepthMetrics struct {
	Depth     atomic.Uint64
	DepthHigh atomic.Uint64
}

func (m *queueDepthMetrics) noteEnqueued() {
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

func (m *queueDepthMetrics) noteDequeued() {
	if m == nil {
		return
	}
	m.Depth.Add(^uint64(0))
}

// WriteQueueMetrics tracks CONNECT-IP forwarder writeCh occupancy (optional test/profiling hook).
type WriteQueueMetrics = queueDepthMetrics

// DownloadQueueMetrics tracks CONNECT-IP forwarder downloadCh occupancy (optional test/profiling hook).
type DownloadQueueMetrics = queueDepthMetrics
