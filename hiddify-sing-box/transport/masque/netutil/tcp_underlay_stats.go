package netutil

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// TCPUnderlayConnSnapshot is one tracked MASQUE TLS-underlay TCP connection.
type TCPUnderlayConnSnapshot struct {
	Role              string `json:"role"`
	Local             string `json:"local,omitempty"`
	Remote            string `json:"remote,omitempty"`
	TCPInfoSnapshot
	TotalRetransDelta uint32  `json:"total_retrans_delta"` // since TrackTCPUnderlay
	LostDelta         uint32  `json:"lost_delta"`
	RetransByteRatio  float64 `json:"retrans_byte_ratio"` // bytes_retrans / bytes_sent (0 if no send)
}

// TCPUnderlayStatsSnapshot aggregates always-on TCP_INFO across tracked underlays.
// iperf inside the tunnel often reports Retr=0 while the VPN TCP retransmits —
// this is the counter that catches that.
type TCPUnderlayStatsSnapshot struct {
	TrackedConns     int                       `json:"tracked_conns"`
	SumTotalRetrans  uint64                    `json:"sum_total_retrans"`
	SumRetransDelta  uint64                    `json:"sum_retrans_delta"`
	SumLost          uint64                    `json:"sum_lost"`
	SumLostDelta     uint64                    `json:"sum_lost_delta"`
	SumBytesSent     uint64                    `json:"sum_bytes_sent"`
	SumBytesRetrans  uint64                    `json:"sum_bytes_retrans"`
	RetransByteRatio float64                   `json:"retrans_byte_ratio"` // sum_bytes_retrans / sum_bytes_sent
	MinRTTUs         uint32                    `json:"min_rtt_us"`
	MaxSndCwnd       uint32                    `json:"max_snd_cwnd"`
	MinSndWnd        uint32                    `json:"min_snd_wnd"`      // peer RWND; 0=unset
	MinRcvSpace      uint32                    `json:"min_rcv_space"`
	MinRcvSsthresh   uint32                    `json:"min_rcv_ssthresh"` // diagnose SO_RCVBUF lock
	Conns            []TCPUnderlayConnSnapshot `json:"conns,omitempty"`
}

type trackedTCPUnderlay struct {
	role          string
	conn          net.Conn
	baseTotalRetr uint32
	baseLost      uint32
	baseSet       bool
}

var (
	tcpUnderlayMu       sync.Mutex
	tcpUnderlayTracked  []*trackedTCPUnderlay
	tcpUnderlayEpoch    atomic.Uint64
	tcpUnderlayDumpOnce sync.Once
)

// TrackTCPUnderlay registers a live MASQUE H2 TLS underlay TCP conn for loss/retrans snapshots.
// Pass the raw TCP (or tls.Conn); TCP_INFO unwraps NetConn when needed. Safe to call repeatedly.
// No-op when built with -tags masque_nostats.
func TrackTCPUnderlay(role string, conn net.Conn) {
	if !masqueStatsEnabled || conn == nil {
		return
	}
	tcpUnderlayMu.Lock()
	defer tcpUnderlayMu.Unlock()
	// Dedup: same remote+local already tracked (e.g. re-track after TLS unwrap).
	la, ra := localAddrString(conn), remoteAddrString(conn)
	for _, t := range tcpUnderlayTracked {
		if t != nil && t.conn != nil && localAddrString(t.conn) == la && remoteAddrString(t.conn) == ra {
			return
		}
	}
	tcpUnderlayTracked = append(tcpUnderlayTracked, &trackedTCPUnderlay{role: role, conn: conn})
	tcpUnderlayEpoch.Add(1)
	EnsureTCPUnderlayStatsFileDump()
}

// SnapshotTCPUnderlayStats samples TCP_INFO on tracked conns and prunes dead ones.
func SnapshotTCPUnderlayStats() TCPUnderlayStatsSnapshot {
	tcpUnderlayMu.Lock()
	defer tcpUnderlayMu.Unlock()

	alive := tcpUnderlayTracked[:0]
	var out TCPUnderlayStatsSnapshot
	for _, t := range tcpUnderlayTracked {
		if t == nil || t.conn == nil {
			continue
		}
		info := ReadTCPInfo(t.conn)
		// Closed sockets often still expose Local/RemoteAddr — rely on TCP_INFO, not addrs.
		if !info.OK || tcpInfoStateClosed(info.State) {
			continue
		}
		if !t.baseSet {
			t.baseTotalRetr = info.TotalRetrans
			t.baseLost = info.Lost
			t.baseSet = true
		}
		deltaRetr := uint32(0)
		if info.TotalRetrans >= t.baseTotalRetr {
			deltaRetr = info.TotalRetrans - t.baseTotalRetr
		}
		deltaLost := uint32(0)
		if info.Lost >= t.baseLost {
			deltaLost = info.Lost - t.baseLost
		}
		ratio := 0.0
		if info.BytesSent > 0 {
			ratio = float64(info.BytesRetrans) / float64(info.BytesSent)
		}
		snap := TCPUnderlayConnSnapshot{
			Role:              t.role,
			Local:             localAddrString(t.conn),
			Remote:            remoteAddrString(t.conn),
			TCPInfoSnapshot:   info,
			TotalRetransDelta: deltaRetr,
			LostDelta:         deltaLost,
			RetransByteRatio:  ratio,
		}
		out.Conns = append(out.Conns, snap)
		out.SumTotalRetrans += uint64(info.TotalRetrans)
		out.SumRetransDelta += uint64(deltaRetr)
		out.SumLost += uint64(info.Lost)
		out.SumLostDelta += uint64(deltaLost)
		out.SumBytesSent += info.BytesSent
		out.SumBytesRetrans += info.BytesRetrans
		if info.RTTUs > 0 && (out.MinRTTUs == 0 || info.RTTUs < out.MinRTTUs) {
			out.MinRTTUs = info.RTTUs
		}
		if info.SndCwnd > out.MaxSndCwnd {
			out.MaxSndCwnd = info.SndCwnd
		}
		if info.SndWnd > 0 && (out.MinSndWnd == 0 || info.SndWnd < out.MinSndWnd) {
			out.MinSndWnd = info.SndWnd
		}
		if info.RcvSpace > 0 && (out.MinRcvSpace == 0 || info.RcvSpace < out.MinRcvSpace) {
			out.MinRcvSpace = info.RcvSpace
		}
		if info.RcvSsthresh > 0 && (out.MinRcvSsthresh == 0 || info.RcvSsthresh < out.MinRcvSsthresh) {
			out.MinRcvSsthresh = info.RcvSsthresh
		}
		alive = append(alive, t)
	}
	tcpUnderlayTracked = alive
	out.TrackedConns = len(alive)
	if out.SumBytesSent > 0 {
		out.RetransByteRatio = float64(out.SumBytesRetrans) / float64(out.SumBytesSent)
	}
	return out
}

func localAddrString(c net.Conn) string {
	if c == nil || c.LocalAddr() == nil {
		return ""
	}
	return c.LocalAddr().String()
}

func remoteAddrString(c net.Conn) string {
	if c == nil || c.RemoteAddr() == nil {
		return ""
	}
	return c.RemoteAddr().String()
}

// tcpInfoStateClosed reports TCP states that should leave the underlay registry.
// Values match Linux include/uapi/linux/tcp.h (TCP_ESTABLISHED=1 … TCP_CLOSING=11).
func tcpInfoStateClosed(state uint8) bool {
	switch state {
	case 5, 6, 7, 8, 9, 11: // FIN_WAIT2, TIME_WAIT, CLOSE, CLOSE_WAIT, LAST_ACK, CLOSING
		return true
	default:
		return false
	}
}

// ResetTCPUnderlayStatsTrackingForTest clears the registry (unit tests only).
func ResetTCPUnderlayStatsTrackingForTest() {
	tcpUnderlayMu.Lock()
	defer tcpUnderlayMu.Unlock()
	tcpUnderlayTracked = nil
}

// EnsureTCPUnderlayStatsFileDump writes SnapshotTCPUnderlayStats JSON ~1 Hz while conns tracked.
// No-op with -tags masque_nostats.
func EnsureTCPUnderlayStatsFileDump() {
	if !masqueStatsEnabled {
		return
	}
	tcpUnderlayDumpOnce.Do(func() {
		path := filepath.Join(os.TempDir(), "masque-tcp-underlay-stats.json")
		go func() {
			t := time.NewTicker(time.Second)
			defer t.Stop()
			for range t.C {
				s := SnapshotTCPUnderlayStats()
				if s.TrackedConns == 0 {
					continue
				}
				type dump struct {
					TCPUnderlayStatsSnapshot
					TsUnixMs int64 `json:"ts_unix_ms"`
				}
				d := dump{TCPUnderlayStatsSnapshot: s, TsUnixMs: time.Now().UnixMilli()}
				raw, err := json.MarshalIndent(d, "", "  ")
				if err != nil {
					continue
				}
				_ = os.WriteFile(path, raw, 0o644)
			}
		}()
	})
}
