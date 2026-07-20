package connectip

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

func init() {
	v := strings.TrimSpace(os.Getenv("MASQUE_CONNECT_IP_RELAY_STATS"))
	if v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes") {
		EnableCIPClientRelayStats()
	}
}

// CIPClientRelayStatsSnapshot is client-side CONNECT-IP write/ingress counters for field scrape.
type CIPClientRelayStatsSnapshot struct {
	WriteOK       uint64
	WriteFail     uint64
	WriteBytes    uint64
	Flush         uint64
	IngressDrops  uint64
	H3PrefetchIn  uint64
	H3PrefetchOut uint64
}

type cipClientRelayStats struct {
	writeOK       atomic.Uint64
	writeFail     atomic.Uint64
	writeBytes    atomic.Uint64
	flush         atomic.Uint64
	h3PrefetchIn  atomic.Uint64
	h3PrefetchOut atomic.Uint64
}

var (
	globalCIPClientRelayStats cipClientRelayStats
	cipClientRelayStatsActive atomic.Bool
	cipClientStatsOnce        atomic.Bool
)

// EnableCIPClientRelayStats turns on client RESULT_CONNECT_IP_CLIENT_STATS emission.
func EnableCIPClientRelayStats() {
	cipClientRelayStatsActive.Store(true)
	if cipClientStatsOnce.CompareAndSwap(false, true) {
		go cipClientStatsTicker()
	}
}

func cipClientRelayStatsEnabled() bool {
	return cipClientRelayStatsActive.Load()
}

func cipClientStatsTicker() {
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for range t.C {
		if !cipClientRelayStatsEnabled() {
			continue
		}
		LogCIPClientRelayStats("client")
		writeCIPClientRelayStatsFile("client")
	}
}

// ResetCIPClientRelayStats clears client counters (tests).
func ResetCIPClientRelayStats() {
	globalCIPClientRelayStats.writeOK.Store(0)
	globalCIPClientRelayStats.writeFail.Store(0)
	globalCIPClientRelayStats.writeBytes.Store(0)
	globalCIPClientRelayStats.flush.Store(0)
	globalCIPClientRelayStats.h3PrefetchIn.Store(0)
	globalCIPClientRelayStats.h3PrefetchOut.Store(0)
}

// SnapshotCIPClientRelayStats returns client write/ingress counters (ingress drops from shared total).
func SnapshotCIPClientRelayStats() CIPClientRelayStatsSnapshot {
	return CIPClientRelayStatsSnapshot{
		WriteOK:       globalCIPClientRelayStats.writeOK.Load(),
		WriteFail:     globalCIPClientRelayStats.writeFail.Load(),
		WriteBytes:    globalCIPClientRelayStats.writeBytes.Load(),
		Flush:         globalCIPClientRelayStats.flush.Load(),
		IngressDrops:  StreamCapsuleDatagramIngressDropTotal(),
		H3PrefetchIn:  globalCIPClientRelayStats.h3PrefetchIn.Load(),
		H3PrefetchOut: globalCIPClientRelayStats.h3PrefetchOut.Load(),
	}
}

func recordCIPClientWriteOK(nBytes int) {
	if !cipClientRelayStatsEnabled() {
		return
	}
	globalCIPClientRelayStats.writeOK.Add(1)
	if nBytes > 0 {
		globalCIPClientRelayStats.writeBytes.Add(uint64(nBytes))
	}
}

func recordCIPClientWriteFail() {
	if cipClientRelayStatsEnabled() {
		globalCIPClientRelayStats.writeFail.Add(1)
	}
}

func recordCIPClientFlush() {
	if cipClientRelayStatsEnabled() {
		globalCIPClientRelayStats.flush.Add(1)
	}
}

func recordCIPClientH3PrefetchIn() {
	if cipClientRelayStatsEnabled() {
		globalCIPClientRelayStats.h3PrefetchIn.Add(1)
	}
}

func recordCIPClientH3PrefetchOut() {
	if cipClientRelayStatsEnabled() {
		globalCIPClientRelayStats.h3PrefetchOut.Add(1)
	}
}

// LogCIPClientRelayStats emits RESULT_CONNECT_IP_CLIENT_STATS for field scrapers.
func LogCIPClientRelayStats(tag string) {
	if !cipClientRelayStatsEnabled() {
		return
	}
	s := SnapshotCIPClientRelayStats()
	log.Printf(
		"RESULT_CONNECT_IP_CLIENT_STATS tag=%s write_ok=%d write_fail=%d write_bytes=%d flush=%d ingress_drops=%d h3_prefetch_in=%d h3_prefetch_out=%d",
		tag,
		s.WriteOK,
		s.WriteFail,
		s.WriteBytes,
		s.Flush,
		s.IngressDrops,
		s.H3PrefetchIn,
		s.H3PrefetchOut,
	)
}

func writeCIPClientRelayStatsFile(tag string) {
	s := SnapshotCIPClientRelayStats()
	type dump struct {
		Tag           string `json:"tag"`
		WriteOK       uint64 `json:"write_ok"`
		WriteFail     uint64 `json:"write_fail"`
		WriteBytes    uint64 `json:"write_bytes"`
		Flush         uint64 `json:"flush"`
		IngressDrops  uint64 `json:"ingress_drops"`
		H3PrefetchIn  uint64 `json:"h3_prefetch_in"`
		H3PrefetchOut uint64 `json:"h3_prefetch_out"`
		TsUnixMs      int64  `json:"ts_unix_ms"`
	}
	d := dump{
		Tag:           tag,
		WriteOK:       s.WriteOK,
		WriteFail:     s.WriteFail,
		WriteBytes:    s.WriteBytes,
		Flush:         s.Flush,
		IngressDrops:  s.IngressDrops,
		H3PrefetchIn:  s.H3PrefetchIn,
		H3PrefetchOut: s.H3PrefetchOut,
		TsUnixMs:      time.Now().UnixMilli(),
	}
	raw, err := json.Marshal(d)
	if err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(os.TempDir(), "masque-connect-ip-client-stats.json"), raw, 0o644)
}
