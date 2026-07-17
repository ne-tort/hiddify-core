package h3

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

// QUICConnStatsSnapshot aggregates always-on loss/RTT counters across tracked
// QUIC connections (client dial / server accept). File dump: masque-quic-stats.json.
// No-op registry when built with -tags masque_nostats.
type QUICConnStatsSnapshot struct {
	TrackedConns        int                     `json:"tracked_conns"`
	BytesSent           uint64                  `json:"bytes_sent"`
	PacketsSent         uint64                  `json:"packets_sent"`
	BytesReceived       uint64                  `json:"bytes_received"`
	PacketsReceived     uint64                  `json:"packets_received"`
	BytesLost           uint64                  `json:"bytes_lost"`
	PacketsLost         uint64                  `json:"packets_lost"`
	SpuriousPacketsLost uint64                  `json:"spurious_packets_lost"`
	// DeclaredLostApprox ≈ PacketsLost+Spurious (quic-go PacketsLost shrinks on spurious recovery).
	DeclaredLostApprox uint64  `json:"declared_lost_approx"`
	LostPacketRatio    float64 `json:"lost_packet_ratio"` // PacketsLost / PacketsSent
	MinRTTNs           int64   `json:"min_rtt_ns"`
	SmoothedRTTNs      int64   `json:"smoothed_rtt_ns"`
	Conns              []QUICConnSnapshot `json:"conns,omitempty"`
}

// QUICConnSnapshot is one tracked QUIC connection.
type QUICConnSnapshot struct {
	Role                string  `json:"role"`
	BytesSent           uint64  `json:"bytes_sent"`
	PacketsSent         uint64  `json:"packets_sent"`
	BytesReceived       uint64  `json:"bytes_received"`
	PacketsReceived     uint64  `json:"packets_received"`
	BytesLost           uint64  `json:"bytes_lost"`
	PacketsLost         uint64  `json:"packets_lost"`
	SpuriousPacketsLost uint64  `json:"spurious_packets_lost"`
	LostPacketRatio     float64 `json:"lost_packet_ratio"`
	MinRTTNs            int64   `json:"min_rtt_ns"`
	SmoothedRTTNs       int64   `json:"smoothed_rtt_ns"`
}

type trackedQUICConn struct {
	role string
	conn *quic.Conn
}

var (
	quicTrackedMu    sync.Mutex
	quicTrackedConns []*trackedQUICConn
	quicTrackEpoch   atomic.Uint64
	quicDumpOnce     sync.Once
)

// TrackQUICConn registers a live QUIC conn for SnapshotQUICConnStats (client+server).
// Safe to call repeatedly; closed/nil conns are pruned on snapshot.
// No-op with -tags masque_nostats.
func TrackQUICConn(role string, conn *quic.Conn) {
	if !masqueStatsEnabled || conn == nil {
		return
	}
	quicTrackedMu.Lock()
	defer quicTrackedMu.Unlock()
	for _, t := range quicTrackedConns {
		if t != nil && t.conn == conn {
			return
		}
	}
	quicTrackedConns = append(quicTrackedConns, &trackedQUICConn{role: role, conn: conn})
	quicTrackEpoch.Add(1)
	EnsureQUICConnStatsFileDump()
}

// SnapshotQUICConnStats returns aggregated ConnectionStats across tracked conns.
func SnapshotQUICConnStats() QUICConnStatsSnapshot {
	if !masqueStatsEnabled {
		return QUICConnStatsSnapshot{}
	}
	quicTrackedMu.Lock()
	defer quicTrackedMu.Unlock()

	alive := quicTrackedConns[:0]
	var out QUICConnStatsSnapshot
	var minRTT, smoothRTT int64
	for _, t := range quicTrackedConns {
		if t == nil || t.conn == nil {
			continue
		}
		select {
		case <-t.conn.Context().Done():
			continue
		default:
		}
		alive = append(alive, t)
		st := t.conn.ConnectionStats()
		ratio := 0.0
		if st.PacketsSent > 0 {
			ratio = float64(st.PacketsLost) / float64(st.PacketsSent)
		}
		snap := QUICConnSnapshot{
			Role:                t.role,
			BytesSent:           st.BytesSent,
			PacketsSent:         st.PacketsSent,
			BytesReceived:       st.BytesReceived,
			PacketsReceived:     st.PacketsReceived,
			BytesLost:           st.BytesLost,
			PacketsLost:         st.PacketsLost,
			SpuriousPacketsLost: st.SpuriousPacketsLost,
			LostPacketRatio:     ratio,
		}
		if st.MinRTT > 0 {
			snap.MinRTTNs = st.MinRTT.Nanoseconds()
			if minRTT == 0 || snap.MinRTTNs < minRTT {
				minRTT = snap.MinRTTNs
			}
		}
		if st.SmoothedRTT > 0 {
			snap.SmoothedRTTNs = st.SmoothedRTT.Nanoseconds()
			if smoothRTT == 0 || snap.SmoothedRTTNs < smoothRTT {
				smoothRTT = snap.SmoothedRTTNs
			}
		}
		out.Conns = append(out.Conns, snap)
		out.BytesSent += st.BytesSent
		out.PacketsSent += st.PacketsSent
		out.BytesReceived += st.BytesReceived
		out.PacketsReceived += st.PacketsReceived
		out.BytesLost += st.BytesLost
		out.PacketsLost += st.PacketsLost
		out.SpuriousPacketsLost += st.SpuriousPacketsLost
	}
	quicTrackedConns = alive
	out.TrackedConns = len(alive)
	out.DeclaredLostApprox = out.PacketsLost + out.SpuriousPacketsLost
	if out.PacketsSent > 0 {
		out.LostPacketRatio = float64(out.PacketsLost) / float64(out.PacketsSent)
	}
	out.MinRTTNs = minRTT
	out.SmoothedRTTNs = smoothRTT
	return out
}

// EnsureQUICConnStatsFileDump writes SnapshotQUICConnStats JSON ~1 Hz while conns tracked.
// Path: $TMPDIR/masque-quic-stats.json. No-op with -tags masque_nostats.
func EnsureQUICConnStatsFileDump() {
	if !masqueStatsEnabled {
		return
	}
	quicDumpOnce.Do(func() {
		path := filepath.Join(os.TempDir(), "masque-quic-stats.json")
		go func() {
			t := time.NewTicker(time.Second)
			defer t.Stop()
			for range t.C {
				s := SnapshotQUICConnStats()
				if s.TrackedConns == 0 {
					continue
				}
				type dump struct {
					QUICConnStatsSnapshot
					TsUnixMs int64 `json:"ts_unix_ms"`
				}
				d := dump{QUICConnStatsSnapshot: s, TsUnixMs: time.Now().UnixMilli()}
				raw, err := json.MarshalIndent(d, "", "  ")
				if err != nil {
					continue
				}
				_ = os.WriteFile(path, raw, 0o644)
			}
		}()
	})
}

// ResetQUICConnStatsTrackingForTest clears the tracked-conn registry (unit tests only).
func ResetQUICConnStatsTrackingForTest() {
	quicTrackedMu.Lock()
	defer quicTrackedMu.Unlock()
	quicTrackedConns = nil
}
