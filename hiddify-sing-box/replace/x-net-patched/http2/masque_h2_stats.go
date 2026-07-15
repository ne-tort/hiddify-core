package http2

import (
	"sync/atomic"
	"time"
)

// MasqueH2Stats is always-on CONNECT Extended CONNECT dataplane counters
// (no getenv). Benches / SnapshotMasqueH2Stats read these to catch WAN FC stalls
// and stream/connection loss (RST/GOAWAY).
type MasqueH2Stats struct {
	DownloadBodyBytes      uint64
	WindowUpdateBytes      uint64
	WindowUpdateCount      uint64
	AwaitFlowControlWaits  uint64
	AwaitFlowControlWaitNs uint64
	PeerStreamWindow       uint32 // last SETTINGS_INITIAL_WINDOW_SIZE from peer (0=unset)
	TransportResets        uint64
	RecvRSTStream          uint64
	RecvGOAWAY             uint64
	RecvGOAWAYErr          uint64 // GOAWAY with non-zero ErrCode
}

var (
	masqueH2DownloadBodyBytes      atomic.Uint64
	masqueH2WindowUpdateBytes      atomic.Uint64
	masqueH2WindowUpdateCount      atomic.Uint64
	masqueH2AwaitFlowControlWaits  atomic.Uint64
	masqueH2AwaitFlowControlWaitNs atomic.Uint64
	masqueH2PeerStreamWindow       atomic.Uint32
	masqueH2TransportResets        atomic.Uint64
	masqueH2RecvRSTStream          atomic.Uint64
	masqueH2RecvGOAWAY             atomic.Uint64
	masqueH2RecvGOAWAYErr          atomic.Uint64
)

func masqueH2NoteDownloadBody(n uint64) {
	if n > 0 {
		masqueH2DownloadBodyBytes.Add(n)
	}
}

func masqueH2NoteWindowUpdate(n uint32) {
	if n == 0 {
		return
	}
	masqueH2WindowUpdateBytes.Add(uint64(n))
	masqueH2WindowUpdateCount.Add(1)
}

func masqueH2NoteAwaitFlowControlWait(d time.Duration) {
	if d <= 0 {
		return
	}
	masqueH2AwaitFlowControlWaits.Add(1)
	masqueH2AwaitFlowControlWaitNs.Add(uint64(d.Nanoseconds()))
}

func masqueH2NotePeerStreamWindow(v uint32) {
	masqueH2PeerStreamWindow.Store(v)
}

// NoteMasqueH2TransportReset increments shared-pool reset counter (session dial retry).
func NoteMasqueH2TransportReset() {
	masqueH2TransportResets.Add(1)
}

func masqueH2NoteRecvRSTStream() {
	masqueH2RecvRSTStream.Add(1)
}

func masqueH2NoteRecvGOAWAY(errCode ErrCode) {
	masqueH2RecvGOAWAY.Add(1)
	if errCode != ErrCodeNo {
		masqueH2RecvGOAWAYErr.Add(1)
	}
}

// SnapshotMasqueH2Stats returns a point-in-time copy of H2 FC/loss-related counters.
func SnapshotMasqueH2Stats() MasqueH2Stats {
	return MasqueH2Stats{
		DownloadBodyBytes:      masqueH2DownloadBodyBytes.Load(),
		WindowUpdateBytes:      masqueH2WindowUpdateBytes.Load(),
		WindowUpdateCount:      masqueH2WindowUpdateCount.Load(),
		AwaitFlowControlWaits:  masqueH2AwaitFlowControlWaits.Load(),
		AwaitFlowControlWaitNs: masqueH2AwaitFlowControlWaitNs.Load(),
		PeerStreamWindow:       masqueH2PeerStreamWindow.Load(),
		TransportResets:        masqueH2TransportResets.Load(),
		RecvRSTStream:          masqueH2RecvRSTStream.Load(),
		RecvGOAWAY:             masqueH2RecvGOAWAY.Load(),
		RecvGOAWAYErr:          masqueH2RecvGOAWAYErr.Load(),
	}
}

// ResetMasqueH2StatsForTest clears counters (unit tests only).
func ResetMasqueH2StatsForTest() {
	masqueH2DownloadBodyBytes.Store(0)
	masqueH2WindowUpdateBytes.Store(0)
	masqueH2WindowUpdateCount.Store(0)
	masqueH2AwaitFlowControlWaits.Store(0)
	masqueH2AwaitFlowControlWaitNs.Store(0)
	masqueH2PeerStreamWindow.Store(0)
	masqueH2TransportResets.Store(0)
	masqueH2RecvRSTStream.Store(0)
	masqueH2RecvGOAWAY.Store(0)
	masqueH2RecvGOAWAYErr.Store(0)
}
