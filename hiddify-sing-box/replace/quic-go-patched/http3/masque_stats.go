package http3

import (
	"sync/atomic"
)

// MasqueConnectStreamStats aggregates CONNECT-stream H3 DATA frame counters (field bench).
type MasqueConnectStreamStats struct {
	DataFrameCount uint64
	DataFrameBytes uint64
}

var masqueConnectStreamStats MasqueConnectStreamStats

// SnapshotMasqueConnectStreamStats returns a copy of global CONNECT-stream dataplane counters.
func SnapshotMasqueConnectStreamStats() MasqueConnectStreamStats {
	return MasqueConnectStreamStats{
		DataFrameCount: atomic.LoadUint64(&masqueConnectStreamStats.DataFrameCount),
		DataFrameBytes: atomic.LoadUint64(&masqueConnectStreamStats.DataFrameBytes),
	}
}

// ResetMasqueConnectStreamStats clears global counters (tests).
func ResetMasqueConnectStreamStats() {
	atomic.StoreUint64(&masqueConnectStreamStats.DataFrameCount, 0)
	atomic.StoreUint64(&masqueConnectStreamStats.DataFrameBytes, 0)
}

func masqueRecordDataFramePayload(n int) {
	if n <= 0 {
		return
	}
	atomic.AddUint64(&masqueConnectStreamStats.DataFrameCount, 1)
	atomic.AddUint64(&masqueConnectStreamStats.DataFrameBytes, uint64(n))
}
