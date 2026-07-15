package h3

import (
	"sync"
	"sync/atomic"

	"github.com/quic-go/quic-go"
)

// QUICConnStatsSnapshot aggregates always-on loss/RTT counters across tracked
// QUIC connections (client dial / server accept). No getenv — benches and field
// dumps call SnapshotQUICConnStats to catch WAN loss spirals early.
type QUICConnStatsSnapshot struct {
	TrackedConns        int
	BytesSent           uint64
	PacketsSent         uint64
	BytesReceived       uint64
	PacketsReceived     uint64
	BytesLost           uint64
	PacketsLost         uint64
	SpuriousPacketsLost uint64
	// MinRTTNs / SmoothedRTTNs are the min across live conns (0 if none report).
	MinRTTNs      int64
	SmoothedRTTNs int64
}

type trackedQUICConn struct {
	role string
	conn *quic.Conn
}

var (
	quicTrackedMu    sync.Mutex
	quicTrackedConns []*trackedQUICConn
	quicTrackEpoch   atomic.Uint64
)

// TrackQUICConn registers a live QUIC conn for SnapshotQUICConnStats (client+server).
// Safe to call repeatedly; closed/nil conns are pruned on snapshot.
func TrackQUICConn(role string, conn *quic.Conn) {
	if conn == nil {
		return
	}
	quicTrackedMu.Lock()
	defer quicTrackedMu.Unlock()
	quicTrackedConns = append(quicTrackedConns, &trackedQUICConn{role: role, conn: conn})
	quicTrackEpoch.Add(1)
}

// SnapshotQUICConnStats returns aggregated ConnectionStats across tracked conns.
func SnapshotQUICConnStats() QUICConnStatsSnapshot {
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
		out.BytesSent += st.BytesSent
		out.PacketsSent += st.PacketsSent
		out.BytesReceived += st.BytesReceived
		out.PacketsReceived += st.PacketsReceived
		out.BytesLost += st.BytesLost
		out.PacketsLost += st.PacketsLost
		out.SpuriousPacketsLost += st.SpuriousPacketsLost
		if st.MinRTT > 0 {
			ns := st.MinRTT.Nanoseconds()
			if minRTT == 0 || ns < minRTT {
				minRTT = ns
			}
		}
		if st.SmoothedRTT > 0 {
			ns := st.SmoothedRTT.Nanoseconds()
			if smoothRTT == 0 || ns < smoothRTT {
				smoothRTT = ns
			}
		}
	}
	quicTrackedConns = alive
	out.TrackedConns = len(alive)
	out.MinRTTNs = minRTT
	out.SmoothedRTTNs = smoothRTT
	return out
}

// ResetQUICConnStatsTrackingForTest clears the tracked-conn registry (unit tests only).
func ResetQUICConnStatsTrackingForTest() {
	quicTrackedMu.Lock()
	defer quicTrackedMu.Unlock()
	quicTrackedConns = nil
}
