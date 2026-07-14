package h3

import (
	"encoding/json"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// Env:
//
//	MASQUE_QUIC_STATS=1              enable tracking + periodic dump/log
//	MASQUE_QUIC_STATS_FILE=/path.json write aggregate snapshot (atomic replace)
//	MASQUE_QUIC_STATS_INTERVAL_SEC=2 dump interval (default 2)
//
// Counters come from quic.Conn.ConnectionStats():
//   PacketsLost / BytesLost = declared lost (SPH) → typically retransmitted by QUIC.
//   They are NOT TCP/iperf retransmits and are NOT "undelivered to the app"
//   (CONNECT-stream still delivers after QUIC recovery).

type quicTrackedConn struct {
	role string // "client" | "server"
	conn *quic.Conn
}

var (
	quicStatsMu       sync.Mutex
	quicStatsTracked  []quicTrackedConn
	quicStatsOnce     sync.Once
	quicStatsFilePath string
)

func quicStatsEnabled() bool {
	v := strings.TrimSpace(os.Getenv("MASQUE_QUIC_STATS"))
	return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
}

// TrackQUICConn registers a live MASQUE QUIC conn for loss/RTT dumps (no-op unless MASQUE_QUIC_STATS=1).
func TrackQUICConn(role string, conn *quic.Conn) {
	if conn == nil || !quicStatsEnabled() {
		return
	}
	role = strings.TrimSpace(role)
	if role == "" {
		role = "unknown"
	}
	quicStatsMu.Lock()
	quicStatsTracked = append(quicStatsTracked, quicTrackedConn{role: role, conn: conn})
	quicStatsMu.Unlock()

	quicStatsOnce.Do(startQUICStatsDumper)

	go func() {
		<-conn.Context().Done()
		quicStatsMu.Lock()
		out := quicStatsTracked[:0]
		for _, t := range quicStatsTracked {
			if t.conn != conn {
				out = append(out, t)
			}
		}
		quicStatsTracked = out
		quicStatsMu.Unlock()
		dumpQUICConnStats("conn_closed")
	}()
}

func startQUICStatsDumper() {
	quicStatsFilePath = strings.TrimSpace(os.Getenv("MASQUE_QUIC_STATS_FILE"))
	if quicStatsFilePath == "" {
		quicStatsFilePath = "/tmp/masque-quic-stats.json"
	}
	interval := 2 * time.Second
	if s := strings.TrimSpace(os.Getenv("MASQUE_QUIC_STATS_INTERVAL_SEC")); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			interval = time.Duration(n) * time.Second
		}
	}
	log.Printf("masque_quic_stats_enabled file=%s interval=%s", quicStatsFilePath, interval)
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for range t.C {
			dumpQUICConnStats("tick")
		}
	}()
}

type quicConnStatsRow struct {
	Role            string  `json:"role"`
	Remote          string  `json:"remote"`
	PacketsSent     uint64  `json:"packets_sent"`
	PacketsReceived uint64  `json:"packets_received"`
	PacketsLost     uint64  `json:"packets_lost"`
	PacketsSpurious uint64  `json:"packets_spurious_lost"`
	BytesSent       uint64  `json:"bytes_sent"`
	BytesReceived   uint64  `json:"bytes_received"`
	BytesLost       uint64  `json:"bytes_lost"`
	LossPctSent     float64 `json:"loss_pct_of_sent"` // outstanding after spurious undo
	CumulLossPctSent float64 `json:"cumul_loss_pct_of_sent"` // PacketsLost+Spurious / sent
	MinRTTMs        float64 `json:"min_rtt_ms"`
	SmoothedRTTMs   float64 `json:"smoothed_rtt_ms"`
	LatestRTTMs     float64 `json:"latest_rtt_ms"`
	Note            string  `json:"note"`
}

type quicConnStatsDump struct {
	TS    string             `json:"ts"`
	Event string             `json:"event"`
	Conns []quicConnStatsRow `json:"conns"`
	Note  string             `json:"note"`
}

func dumpQUICConnStats(event string) {
	quicStatsMu.Lock()
	tracked := append([]quicTrackedConn(nil), quicStatsTracked...)
	path := quicStatsFilePath
	quicStatsMu.Unlock()

	rows := make([]quicConnStatsRow, 0, len(tracked))
	for _, t := range tracked {
		if t.conn == nil {
			continue
		}
		st := t.conn.ConnectionStats()
		lossPct := 0.0
		cumulPct := 0.0
		if st.PacketsSent > 0 {
			lossPct = 100.0 * float64(st.PacketsLost) / float64(st.PacketsSent)
			// Cumulative declares ≈ outstanding + proven-spurious events.
			cumulPct = 100.0 * float64(st.PacketsLost+st.SpuriousPacketsLost) / float64(st.PacketsSent)
		}
		remote := ""
		if ra := t.conn.RemoteAddr(); ra != nil {
			remote = ra.String()
		}
		rows = append(rows, quicConnStatsRow{
			Role:             t.role,
			Remote:           remote,
			PacketsSent:      st.PacketsSent,
			PacketsReceived:  st.PacketsReceived,
			PacketsLost:      st.PacketsLost,
			PacketsSpurious:  st.SpuriousPacketsLost,
			BytesSent:        st.BytesSent,
			BytesReceived:    st.BytesReceived,
			BytesLost:        st.BytesLost,
			LossPctSent:      round1(lossPct),
			CumulLossPctSent: round1(cumulPct),
			MinRTTMs:         float64(st.MinRTT.Microseconds()) / 1000.0,
			SmoothedRTTMs:    float64(st.SmoothedRTT.Microseconds()) / 1000.0,
			LatestRTTMs:      float64(st.LatestRTT.Microseconds()) / 1000.0,
			Note:             "packets_lost=outstanding (decrements on spurious); packets_spurious_lost=false-positive count; cumul_loss_pct=(lost+spurious)/sent",
		})
	}
	dump := quicConnStatsDump{
		TS:    time.Now().UTC().Format(time.RFC3339),
		Event: event,
		Conns: rows,
		Note:  "QUIC path loss only — not iperf TCP retransmits (those are localhost in keep topology)",
	}
	b, err := json.Marshal(dump)
	if err != nil {
		return
	}
	if len(rows) > 0 {
		log.Printf("masque_quic_stats %s", string(b))
	}
	if path == "" {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}

func round1(v float64) float64 {
	return float64(int(v*10+0.5)) / 10
}

// SnapshotQUICConnStats forces an immediate dump (tests / scripts via keepalive).
func SnapshotQUICConnStats() {
	if !quicStatsEnabled() {
		return
	}
	dumpQUICConnStats("snapshot")
}
