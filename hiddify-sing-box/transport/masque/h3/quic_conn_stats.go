package h3

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// QUICConnStatsSnapshot aggregates always-on loss/RTT counters across tracked
// QUIC connections (client dial / server accept). File dump: masque-quic-stats.json.
// No-op registry when built with -tags masque_nostats.
type QUICConnStatsSnapshot struct {
	TrackedConns        int     `json:"tracked_conns"`
	BytesSent           uint64  `json:"bytes_sent"`
	PacketsSent         uint64  `json:"packets_sent"`
	BytesReceived       uint64  `json:"bytes_received"`
	PacketsReceived     uint64  `json:"packets_received"`
	BytesLost           uint64  `json:"bytes_lost"`
	PacketsLost         uint64  `json:"packets_lost"`
	SpuriousPacketsLost uint64  `json:"spurious_packets_lost"`
	// DeclaredLostApprox ≈ PacketsLost+Spurious (quic-go PacketsLost shrinks on spurious recovery).
	DeclaredLostApprox uint64  `json:"declared_lost_approx"`
	LostPacketRatio    float64 `json:"lost_packet_ratio"` // PacketsLost / PacketsSent
	MinRTTNs           int64   `json:"min_rtt_ns"`
	LatestRTTNs        int64   `json:"latest_rtt_ns"`
	SmoothedRTTNs      int64   `json:"smoothed_rtt_ns"`
	MeanDeviationNs    int64   `json:"mean_deviation_ns"`
	CongestionWindow   uint64  `json:"congestion_window"`
	BytesInFlight      uint64  `json:"bytes_in_flight"`
	SendMode           string  `json:"send_mode"`
	InSlowStart        bool    `json:"in_slow_start"`
	InRecovery         bool    `json:"in_recovery"`
	BlockMode          string  `json:"block_mode"`
	DatagramSendBacklog int    `json:"datagram_send_backlog"`
	// Process-wide DATAGRAM drops *before* CONNECT-UDP relay c2s_in (AUDIT B2 / TASKS F0.4).
	DatagramRcvQueueDrops         uint64 `json:"datagram_rcv_queue_drops"`
	StreamDatagramQueueDrops      uint64 `json:"stream_datagram_queue_drops"`
	StreamDatagramRecvClosedDrops uint64 `json:"stream_datagram_recv_closed_drops"`
	UnknownStreamDatagramDrops    uint64 `json:"unknown_stream_datagram_drops"`
	DatagramQueueDropsTotal       uint64 `json:"datagram_queue_drops_total"`
	Conns                         []QUICConnSnapshot `json:"conns,omitempty"`
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
	LatestRTTNs         int64   `json:"latest_rtt_ns"`
	SmoothedRTTNs       int64   `json:"smoothed_rtt_ns"`
	MeanDeviationNs     int64   `json:"mean_deviation_ns"`
	CongestionWindow    uint64  `json:"congestion_window"`
	BytesInFlight       uint64  `json:"bytes_in_flight"`
	SendMode            string  `json:"send_mode"`
	InSlowStart         bool    `json:"in_slow_start"`
	InRecovery          bool    `json:"in_recovery"`
	BlockMode           string  `json:"block_mode"`
	DatagramSendBacklog int     `json:"datagram_send_backlog"`
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
	var minRTT, latestRTT, smoothRTT, meanDev int64
	var maxCwnd, maxBif uint64
	var sendMode, blockMode string
	var dgBacklog int
	var inSlowStart, inRecovery bool
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
		cc := t.conn.ConnectionCongestionStats()
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
		snap.CongestionWindow = cc.CongestionWindow
		snap.BytesInFlight = cc.BytesInFlight
		snap.SendMode = cc.SendMode
		snap.InSlowStart = cc.InSlowStart
		snap.InRecovery = cc.InRecovery
		snap.BlockMode = cc.BlockMode
		snap.DatagramSendBacklog = cc.DatagramSendBacklog
		if cc.CongestionWindow > maxCwnd {
			maxCwnd = cc.CongestionWindow
		}
		if cc.BytesInFlight > maxBif {
			maxBif = cc.BytesInFlight
		}
		if cc.SendMode != "" {
			sendMode = cc.SendMode
		}
		if cc.BlockMode != "" && cc.BlockMode != "none" {
			blockMode = cc.BlockMode
		} else if blockMode == "" {
			blockMode = cc.BlockMode
		}
		if cc.DatagramSendBacklog > dgBacklog {
			dgBacklog = cc.DatagramSendBacklog
		}
		if cc.InSlowStart {
			inSlowStart = true
		}
		if cc.InRecovery {
			inRecovery = true
		}
		if st.MinRTT > 0 {
			snap.MinRTTNs = st.MinRTT.Nanoseconds()
			if minRTT == 0 || snap.MinRTTNs < minRTT {
				minRTT = snap.MinRTTNs
			}
		}
		if st.LatestRTT > 0 {
			snap.LatestRTTNs = st.LatestRTT.Nanoseconds()
			// Prefer the largest latest sample across conns (load path, not quiet peer).
			if snap.LatestRTTNs > latestRTT {
				latestRTT = snap.LatestRTTNs
			}
		}
		if st.SmoothedRTT > 0 {
			snap.SmoothedRTTNs = st.SmoothedRTT.Nanoseconds()
			// Prefer max SRTT — min hid client inflate when aggregating.
			if snap.SmoothedRTTNs > smoothRTT {
				smoothRTT = snap.SmoothedRTTNs
			}
		}
		if st.MeanDeviation > 0 {
			snap.MeanDeviationNs = st.MeanDeviation.Nanoseconds()
			if snap.MeanDeviationNs > meanDev {
				meanDev = snap.MeanDeviationNs
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
	out.LatestRTTNs = latestRTT
	out.SmoothedRTTNs = smoothRTT
	out.MeanDeviationNs = meanDev
	out.CongestionWindow = maxCwnd
	out.BytesInFlight = maxBif
	out.SendMode = sendMode
	out.InSlowStart = inSlowStart
	out.InRecovery = inRecovery
	out.BlockMode = blockMode
	out.DatagramSendBacklog = dgBacklog
	fillQUICDatagramQueueDrops(&out)
	return out
}

func fillQUICDatagramQueueDrops(out *QUICConnStatsSnapshot) {
	if out == nil {
		return
	}
	out.DatagramRcvQueueDrops = quic.DatagramReceiveQueueDropTotal()
	out.StreamDatagramQueueDrops = http3.StreamDatagramQueueDropTotal()
	out.StreamDatagramRecvClosedDrops = http3.StreamDatagramRecvClosedDropTotal()
	out.UnknownStreamDatagramDrops = http3.UnknownStreamDatagramDropTotal()
	out.DatagramQueueDropsTotal = out.DatagramRcvQueueDrops +
		out.StreamDatagramQueueDrops +
		out.StreamDatagramRecvClosedDrops +
		out.UnknownStreamDatagramDrops
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
				if s.TrackedConns == 0 && s.DatagramQueueDropsTotal == 0 {
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
