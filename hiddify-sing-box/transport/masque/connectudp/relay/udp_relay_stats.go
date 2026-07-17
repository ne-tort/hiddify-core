package relay

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
	// Field/bench: MASQUE_UDP_RELAY_STATS=1 enables RESULT_RELAY_STATS without in-proc EnableRelayStatsForBench.
	v := strings.TrimSpace(os.Getenv("MASQUE_UDP_RELAY_STATS"))
	if v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes") {
		EnableRelayStatsForBench()
	}
}

// UDPRelayStatsSnapshot is a point-in-time CONNECT-UDP server relay counter set (UDP-5m1).
type UDPRelayStatsSnapshot struct {
	C2SDatagramIn    uint64
	C2SUDPPayloadOut uint64
	C2SDropMalformed uint64
	C2SDropOversize  uint64
	S2CUDPIn         uint64
	S2CDatagramOut   uint64
	S2CDropOversize  uint64
	S2CDropSendFail  uint64
	// Hotpath attribution (bench only; zero overhead when relayStatsActive=false).
	C2SBatchFlushes uint64
	S2CBatchReads   uint64
	S2CBatchPkts    uint64
	S2CSendSpins    uint64
}

type udpRelayStats struct {
	c2sDatagramIn    atomic.Uint64
	c2sUDPPayloadOut atomic.Uint64
	c2sDropMalformed atomic.Uint64
	c2sDropOversize  atomic.Uint64
	s2cUDPIn         atomic.Uint64
	s2cDatagramOut   atomic.Uint64
	s2cDropOversize  atomic.Uint64
	s2cDropSendFail  atomic.Uint64
	c2sBatchFlushes  atomic.Uint64
	s2cBatchReads    atomic.Uint64
	s2cBatchPkts     atomic.Uint64
	s2cSendSpins     atomic.Uint64
}

var globalUDPRelayStats udpRelayStats

// relayStatsActive is bench-only (EnableRelayStatsForBench); prod hot path checks once per batch.
var relayStatsActive atomic.Bool

func relayStatsEnabled() bool {
	return relayStatsActive.Load()
}

// EnableRelayStatsForBench turns on relay counters for segment localize gates.
func EnableRelayStatsForBench() {
	relayStatsActive.Store(true)
}

// beginRelaySessionStats resets counters when stats are active; returns an end hook for defer.
// While the session is open, emits RESULT_RELAY_STATS ~2 Hz so bench can scrape before teardown.
func beginRelaySessionStats(tag string) func() {
	if !relayStatsEnabled() {
		return func() {}
	}
	ResetUDPRelayStats()
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(500 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				LogUDPRelayStats(tag)
				writeUDPRelayStatsFile(tag)
			}
		}
	}()
	return func() {
		close(stop)
		<-done
		LogUDPRelayStats(tag)
		writeUDPRelayStatsFile(tag)
	}
}

func writeUDPRelayStatsFile(tag string) {
	s := SnapshotUDPRelayStats()
	type dump struct {
		Tag              string `json:"tag"`
		C2SIn            uint64 `json:"c2s_in"`
		C2SUDPOut        uint64 `json:"c2s_udp_out"`
		C2SDropMalformed uint64 `json:"c2s_drop_malformed"`
		C2SDropOversize  uint64 `json:"c2s_drop_oversize"`
		S2CUDPIn         uint64 `json:"s2c_udp_in"`
		S2CDgramOut      uint64 `json:"s2c_dgram_out"`
		S2CDropOversize  uint64 `json:"s2c_drop_oversize"`
		S2CDropSend      uint64 `json:"s2c_drop_send"`
		TsUnixMs         int64  `json:"ts_unix_ms"`
	}
	d := dump{
		Tag:              tag,
		C2SIn:            s.C2SDatagramIn,
		C2SUDPOut:        s.C2SUDPPayloadOut,
		C2SDropMalformed: s.C2SDropMalformed,
		C2SDropOversize:  s.C2SDropOversize,
		S2CUDPIn:         s.S2CUDPIn,
		S2CDgramOut:      s.S2CDatagramOut,
		S2CDropOversize:  s.S2CDropOversize,
		S2CDropSend:      s.S2CDropSendFail,
		TsUnixMs:         time.Now().UnixMilli(),
	}
	raw, err := json.Marshal(d)
	if err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(os.TempDir(), "masque-udp-relay-stats.json"), raw, 0o644)
}

// BeginRelaySessionStats is the exported hook for H2/H3 CONNECT-UDP handlers (bench attribution).
func BeginRelaySessionStats(tag string) func() {
	return beginRelaySessionStats(tag)
}

// ResetUDPRelayStats clears process-wide relay counters (bench isolation).
func ResetUDPRelayStats() {
	globalUDPRelayStats = udpRelayStats{}
}

// SnapshotUDPRelayStats returns current relay counters.
func SnapshotUDPRelayStats() UDPRelayStatsSnapshot {
	return UDPRelayStatsSnapshot{
		C2SDatagramIn:    globalUDPRelayStats.c2sDatagramIn.Load(),
		C2SUDPPayloadOut: globalUDPRelayStats.c2sUDPPayloadOut.Load(),
		C2SDropMalformed: globalUDPRelayStats.c2sDropMalformed.Load(),
		C2SDropOversize:  globalUDPRelayStats.c2sDropOversize.Load(),
		S2CUDPIn:         globalUDPRelayStats.s2cUDPIn.Load(),
		S2CDatagramOut:   globalUDPRelayStats.s2cDatagramOut.Load(),
		S2CDropOversize:  globalUDPRelayStats.s2cDropOversize.Load(),
		S2CDropSendFail:  globalUDPRelayStats.s2cDropSendFail.Load(),
		C2SBatchFlushes:  globalUDPRelayStats.c2sBatchFlushes.Load(),
		S2CBatchReads:    globalUDPRelayStats.s2cBatchReads.Load(),
		S2CBatchPkts:     globalUDPRelayStats.s2cBatchPkts.Load(),
		S2CSendSpins:     globalUDPRelayStats.s2cSendSpins.Load(),
	}
}

func recordRelayC2SBatchFlush() {
	if relayStatsEnabled() {
		globalUDPRelayStats.c2sBatchFlushes.Add(1)
	}
}

func recordRelayS2CBatch(payloads [][]byte) {
	if !relayStatsEnabled() || len(payloads) == 0 {
		return
	}
	globalUDPRelayStats.s2cBatchReads.Add(1)
	globalUDPRelayStats.s2cBatchPkts.Add(uint64(len(payloads)))
}

func recordRelayS2CSendSpins(spins int) {
	if relayStatsEnabled() && spins > 0 {
		globalUDPRelayStats.s2cSendSpins.Add(uint64(spins))
	}
}

func (d UDPRelayStatsSnapshot) Delta(before UDPRelayStatsSnapshot) UDPRelayStatsSnapshot {
	return UDPRelayStatsSnapshot{
		C2SDatagramIn:    d.C2SDatagramIn - before.C2SDatagramIn,
		C2SUDPPayloadOut: d.C2SUDPPayloadOut - before.C2SUDPPayloadOut,
		C2SDropMalformed: d.C2SDropMalformed - before.C2SDropMalformed,
		C2SDropOversize:  d.C2SDropOversize - before.C2SDropOversize,
		S2CUDPIn:         d.S2CUDPIn - before.S2CUDPIn,
		S2CDatagramOut:   d.S2CDatagramOut - before.S2CDatagramOut,
		S2CDropOversize:  d.S2CDropOversize - before.S2CDropOversize,
		S2CDropSendFail:  d.S2CDropSendFail - before.S2CDropSendFail,
		C2SBatchFlushes:  d.C2SBatchFlushes - before.C2SBatchFlushes,
		S2CBatchReads:    d.S2CBatchReads - before.S2CBatchReads,
		S2CBatchPkts:     d.S2CBatchPkts - before.S2CBatchPkts,
		S2CSendSpins:     d.S2CSendSpins - before.S2CSendSpins,
	}
}

// LogUDPRelayStats emits a machine-parseable bench line when relay stats are enabled in-process.
func LogUDPRelayStats(tag string) {
	if !relayStatsEnabled() {
		return
	}
	s := SnapshotUDPRelayStats()
	log.Printf(
		"RESULT_RELAY_STATS tag=%s c2s_in=%d c2s_udp_out=%d c2s_drop_malformed=%d c2s_drop_oversize=%d s2c_udp_in=%d s2c_dgram_out=%d s2c_drop_oversize=%d s2c_drop_send=%d c2s_batch_flush=%d s2c_batch_reads=%d s2c_batch_pkts=%d s2c_send_spins=%d",
		tag,
		s.C2SDatagramIn,
		s.C2SUDPPayloadOut,
		s.C2SDropMalformed,
		s.C2SDropOversize,
		s.S2CUDPIn,
		s.S2CDatagramOut,
		s.S2CDropOversize,
		s.S2CDropSendFail,
		s.C2SBatchFlushes,
		s.S2CBatchReads,
		s.S2CBatchPkts,
		s.S2CSendSpins,
	)
}

