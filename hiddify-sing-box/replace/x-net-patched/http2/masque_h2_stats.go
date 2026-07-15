package http2

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
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
	LocalStreamRecvWindow  uint32 // last client SETTINGS_INITIAL_WINDOW_SIZE we announced
	LocalConnRecvBump      uint32 // last client WINDOW_UPDATE(0) bump at conn open
	// Server-side download send (outflow) — min(stream,conn) seen at DATA Consume.
	ServerSendAvailLast int32
	ServerSendAvailMin  int32 // 0 = unset; tracks minimum observed positive avail
	ServerConnOutflow   int32 // sc.flow.n after last conn WINDOW_UPDATE / sample
	ServerStreamOutflow int32 // st.flow.n sample at DATA Consume
	ServerConnWUBytes   uint64
	TransportResets     uint64
	RecvRSTStream       uint64
	RecvGOAWAY          uint64
	RecvGOAWAYErr       uint64 // GOAWAY with non-zero ErrCode
}

var (
	masqueH2DownloadBodyBytes      atomic.Uint64
	masqueH2WindowUpdateBytes      atomic.Uint64
	masqueH2WindowUpdateCount      atomic.Uint64
	masqueH2AwaitFlowControlWaits  atomic.Uint64
	masqueH2AwaitFlowControlWaitNs atomic.Uint64
	masqueH2PeerStreamWindow       atomic.Uint32
	masqueH2LocalStreamRecvWindow  atomic.Uint32
	masqueH2LocalConnRecvBump      atomic.Uint32
	masqueH2ServerSendAvailLast    atomic.Int32
	masqueH2ServerSendAvailMin     atomic.Int32
	masqueH2ServerConnOutflow      atomic.Int32
	masqueH2ServerStreamOutflow    atomic.Int32
	masqueH2ServerConnWUBytes      atomic.Uint64
	masqueH2TransportResets        atomic.Uint64
	masqueH2RecvRSTStream          atomic.Uint64
	masqueH2RecvGOAWAY             atomic.Uint64
	masqueH2RecvGOAWAYErr          atomic.Uint64
	masqueH2FCDumpOnce             sync.Once
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

func masqueH2NoteLocalRecvWindows(streamIW, connBump uint32) {
	if streamIW > 0 {
		masqueH2LocalStreamRecvWindow.Store(streamIW)
	}
	if connBump > 0 {
		masqueH2LocalConnRecvBump.Store(connBump)
	}
}

// masqueH2NoteServerSendAvail records server outbound flow available() at DATA Consume
// and samples stream/conn outflow levels (download send diagnosis on WAN).
func masqueH2NoteServerSendAvail(avail, streamN, connN int32) {
	masqueH2ServerSendAvailLast.Store(avail)
	masqueH2ServerStreamOutflow.Store(streamN)
	masqueH2ServerConnOutflow.Store(connN)
	if avail <= 0 {
		return
	}
	for {
		cur := masqueH2ServerSendAvailMin.Load()
		if cur != 0 && cur <= avail {
			return
		}
		if masqueH2ServerSendAvailMin.CompareAndSwap(cur, avail) {
			return
		}
	}
}

func masqueH2NoteServerConnWindowUpdate(inc uint32) {
	if inc == 0 {
		return
	}
	masqueH2ServerConnWUBytes.Add(uint64(inc))
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
		LocalStreamRecvWindow:  masqueH2LocalStreamRecvWindow.Load(),
		LocalConnRecvBump:      masqueH2LocalConnRecvBump.Load(),
		ServerSendAvailLast:    masqueH2ServerSendAvailLast.Load(),
		ServerSendAvailMin:     masqueH2ServerSendAvailMin.Load(),
		ServerConnOutflow:      masqueH2ServerConnOutflow.Load(),
		ServerStreamOutflow:    masqueH2ServerStreamOutflow.Load(),
		ServerConnWUBytes:      masqueH2ServerConnWUBytes.Load(),
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
	masqueH2LocalStreamRecvWindow.Store(0)
	masqueH2LocalConnRecvBump.Store(0)
	masqueH2ServerSendAvailLast.Store(0)
	masqueH2ServerSendAvailMin.Store(0)
	masqueH2ServerConnOutflow.Store(0)
	masqueH2ServerStreamOutflow.Store(0)
	masqueH2ServerConnWUBytes.Store(0)
	masqueH2TransportResets.Store(0)
	masqueH2RecvRSTStream.Store(0)
	masqueH2RecvGOAWAY.Store(0)
	masqueH2RecvGOAWAYErr.Store(0)
}

// EnsureMasqueH2FCStatsFileDump writes SnapshotMasqueH2Stats JSON to
// <tmpdir>/masque-h2-fc-stats.json at most ~1 Hz (client body growth or server send samples).
func EnsureMasqueH2FCStatsFileDump() {
	masqueH2FCDumpOnce.Do(func() {
		path := filepath.Join(os.TempDir(), "masque-h2-fc-stats.json")
		go func() {
			var lastBody uint64
			var lastSrvWU uint64
			t := time.NewTicker(time.Second)
			defer t.Stop()
			for range t.C {
				s := SnapshotMasqueH2Stats()
				idle := s.DownloadBodyBytes == 0 && s.LocalStreamRecvWindow == 0 &&
					s.ServerConnWUBytes == 0 && s.ServerSendAvailLast == 0
				if idle {
					continue
				}
				unchanged := s.DownloadBodyBytes == lastBody && s.ServerConnWUBytes == lastSrvWU &&
					s.DownloadBodyBytes != 0
				if unchanged {
					continue
				}
				lastBody = s.DownloadBodyBytes
				lastSrvWU = s.ServerConnWUBytes
				type dump struct {
					MasqueH2Stats
					AwaitFCAvgMs   float64 `json:"await_fc_avg_ms"`
					WUBytesPerBody float64 `json:"wu_bytes_per_body"`
					TsUnixMs       int64   `json:"ts_unix_ms"`
				}
				d := dump{MasqueH2Stats: s, TsUnixMs: time.Now().UnixMilli()}
				if s.AwaitFlowControlWaits > 0 {
					d.AwaitFCAvgMs = float64(s.AwaitFlowControlWaitNs) / float64(s.AwaitFlowControlWaits) / 1e6
				}
				if s.DownloadBodyBytes > 0 {
					d.WUBytesPerBody = float64(s.WindowUpdateBytes) / float64(s.DownloadBodyBytes)
				}
				raw, err := json.MarshalIndent(d, "", "  ")
				if err != nil {
					continue
				}
				_ = os.WriteFile(path, raw, 0o644)
			}
		}()
	})
}
