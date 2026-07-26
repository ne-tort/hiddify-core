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
	// GATE-H2-UNDERLAY: H2 pipe Writes (actual io.Writer.Write to upload body).
	H2PipeWrite uint64
	// H2VisFlush is small-N visibility coalesce flushes (pending → pipe).
	H2VisFlush uint64
	// Pipe wait: time blocked on full async queue or wake wait-for-pipe (µs totals).
	H2PipeWaitUsTotal uint64
	H2PipeWaitCount   uint64
	H2PipeWaitUsMax   uint64
	H2PipeQueueFull   uint64 // times enqueue hit full channel (pre-block)
	// S2C return path: capsule enqueue → ReadPacket deliver; ReadPacket → TUN inject.
	S2CPrefetchSojournUsTotal uint64
	S2CPrefetchSojournCount   uint64
	S2CPrefetchSojournUsMax   uint64
	S2CPrefetchQHigh          uint64
	S2CInjectUsTotal          uint64
	S2CInjectCount            uint64
	S2CInjectUsMax            uint64
	// Inter-ACK TUN inject gaps (pure ACK-only S2C → TUN).
	AckInjectGapUsTotal uint64
	AckInjectGapUsMax   uint64
	AckInjectGapN       uint64
	// Inter-C2S WritePacket gaps (client emit cadence).
	C2SWriteGapUsTotal uint64
	C2SWriteGapUsMax   uint64
	C2SWriteGapN       uint64
	C2SWriteGapGt1ms   uint64
	C2SWriteGapGt5ms   uint64
}

type cipClientRelayStats struct {
	writeOK         atomic.Uint64
	writeFail       atomic.Uint64
	writeBytes      atomic.Uint64
	flush           atomic.Uint64
	h3PrefetchIn    atomic.Uint64
	h3PrefetchOut   atomic.Uint64
	h2PipeWrite     atomic.Uint64
	h2VisFlush      atomic.Uint64
	h2PipeWaitUs    atomic.Uint64
	h2PipeWaitCount atomic.Uint64
	h2PipeWaitUsMax atomic.Uint64
	h2PipeQueueFull atomic.Uint64
	s2cPrefetchSojournUs    atomic.Uint64
	s2cPrefetchSojournCount atomic.Uint64
	s2cPrefetchSojournUsMax atomic.Uint64
	s2cPrefetchQHigh        atomic.Uint64
	s2cInjectUs             atomic.Uint64
	s2cInjectCount          atomic.Uint64
	s2cInjectUsMax          atomic.Uint64
	ackInjectGapUsTotal     atomic.Uint64
	ackInjectGapUsMax       atomic.Uint64
	ackInjectGapN           atomic.Uint64
	lastAckInjectNs         atomic.Int64
	c2sWriteGapUsTotal      atomic.Uint64
	c2sWriteGapUsMax        atomic.Uint64
	c2sWriteGapN            atomic.Uint64
	c2sWriteGapGt1ms        atomic.Uint64
	c2sWriteGapGt5ms        atomic.Uint64
	lastC2SWriteNs          atomic.Int64
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
	globalCIPClientRelayStats.h2PipeWrite.Store(0)
	globalCIPClientRelayStats.h2VisFlush.Store(0)
	globalCIPClientRelayStats.h2PipeWaitUs.Store(0)
	globalCIPClientRelayStats.h2PipeWaitCount.Store(0)
	globalCIPClientRelayStats.h2PipeWaitUsMax.Store(0)
	globalCIPClientRelayStats.h2PipeQueueFull.Store(0)
	globalCIPClientRelayStats.s2cPrefetchSojournUs.Store(0)
	globalCIPClientRelayStats.s2cPrefetchSojournCount.Store(0)
	globalCIPClientRelayStats.s2cPrefetchSojournUsMax.Store(0)
	globalCIPClientRelayStats.s2cPrefetchQHigh.Store(0)
	globalCIPClientRelayStats.s2cInjectUs.Store(0)
	globalCIPClientRelayStats.s2cInjectCount.Store(0)
	globalCIPClientRelayStats.s2cInjectUsMax.Store(0)
	globalCIPClientRelayStats.ackInjectGapUsTotal.Store(0)
	globalCIPClientRelayStats.ackInjectGapUsMax.Store(0)
	globalCIPClientRelayStats.ackInjectGapN.Store(0)
	globalCIPClientRelayStats.lastAckInjectNs.Store(0)
	globalCIPClientRelayStats.c2sWriteGapUsTotal.Store(0)
	globalCIPClientRelayStats.c2sWriteGapUsMax.Store(0)
	globalCIPClientRelayStats.c2sWriteGapN.Store(0)
	globalCIPClientRelayStats.c2sWriteGapGt1ms.Store(0)
	globalCIPClientRelayStats.c2sWriteGapGt5ms.Store(0)
	globalCIPClientRelayStats.lastC2SWriteNs.Store(0)
}

// SnapshotCIPClientRelayStats returns client write/ingress counters (ingress drops from shared total).
func SnapshotCIPClientRelayStats() CIPClientRelayStatsSnapshot {
	return CIPClientRelayStatsSnapshot{
		WriteOK:           globalCIPClientRelayStats.writeOK.Load(),
		WriteFail:         globalCIPClientRelayStats.writeFail.Load(),
		WriteBytes:        globalCIPClientRelayStats.writeBytes.Load(),
		Flush:             globalCIPClientRelayStats.flush.Load(),
		IngressDrops:      StreamCapsuleDatagramIngressDropTotal(),
		H3PrefetchIn:      globalCIPClientRelayStats.h3PrefetchIn.Load(),
		H3PrefetchOut:     globalCIPClientRelayStats.h3PrefetchOut.Load(),
		H2PipeWrite:       globalCIPClientRelayStats.h2PipeWrite.Load(),
		H2VisFlush:        globalCIPClientRelayStats.h2VisFlush.Load(),
		H2PipeWaitUsTotal:         globalCIPClientRelayStats.h2PipeWaitUs.Load(),
		H2PipeWaitCount:           globalCIPClientRelayStats.h2PipeWaitCount.Load(),
		H2PipeWaitUsMax:           globalCIPClientRelayStats.h2PipeWaitUsMax.Load(),
		H2PipeQueueFull:           globalCIPClientRelayStats.h2PipeQueueFull.Load(),
		S2CPrefetchSojournUsTotal: globalCIPClientRelayStats.s2cPrefetchSojournUs.Load(),
		S2CPrefetchSojournCount:   globalCIPClientRelayStats.s2cPrefetchSojournCount.Load(),
		S2CPrefetchSojournUsMax:   globalCIPClientRelayStats.s2cPrefetchSojournUsMax.Load(),
		S2CPrefetchQHigh:          globalCIPClientRelayStats.s2cPrefetchQHigh.Load(),
		S2CInjectUsTotal:          globalCIPClientRelayStats.s2cInjectUs.Load(),
		S2CInjectCount:            globalCIPClientRelayStats.s2cInjectCount.Load(),
		S2CInjectUsMax:            globalCIPClientRelayStats.s2cInjectUsMax.Load(),
		AckInjectGapUsTotal:       globalCIPClientRelayStats.ackInjectGapUsTotal.Load(),
		AckInjectGapUsMax:         globalCIPClientRelayStats.ackInjectGapUsMax.Load(),
		AckInjectGapN:             globalCIPClientRelayStats.ackInjectGapN.Load(),
		C2SWriteGapUsTotal:        globalCIPClientRelayStats.c2sWriteGapUsTotal.Load(),
		C2SWriteGapUsMax:          globalCIPClientRelayStats.c2sWriteGapUsMax.Load(),
		C2SWriteGapN:              globalCIPClientRelayStats.c2sWriteGapN.Load(),
		C2SWriteGapGt1ms:          globalCIPClientRelayStats.c2sWriteGapGt1ms.Load(),
		C2SWriteGapGt5ms:          globalCIPClientRelayStats.c2sWriteGapGt5ms.Load(),
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
	now := time.Now().UnixNano()
	prev := globalCIPClientRelayStats.lastC2SWriteNs.Swap(now)
	if prev <= 0 {
		return
	}
	d := time.Duration(now - prev)
	if d < 0 {
		return
	}
	us := uint64(d.Microseconds())
	if us == 0 && d > 0 {
		us = 1
	}
	globalCIPClientRelayStats.c2sWriteGapUsTotal.Add(us)
	globalCIPClientRelayStats.c2sWriteGapN.Add(1)
	if us > 1000 {
		globalCIPClientRelayStats.c2sWriteGapGt1ms.Add(1)
	}
	if us > 5000 {
		globalCIPClientRelayStats.c2sWriteGapGt5ms.Add(1)
	}
	for {
		cur := globalCIPClientRelayStats.c2sWriteGapUsMax.Load()
		if us <= cur || globalCIPClientRelayStats.c2sWriteGapUsMax.CompareAndSwap(cur, us) {
			return
		}
	}
}

func recordCIPClientWriteFail() {
	if !cipClientRelayStatsEnabled() {
		return
	}
	globalCIPClientRelayStats.writeFail.Add(1)
}

func recordCIPClientFlush() {
	if !cipClientRelayStatsEnabled() {
		return
	}
	globalCIPClientRelayStats.flush.Add(1)
}

func recordCIPClientH3PrefetchIn() {
	if !cipClientRelayStatsEnabled() {
		return
	}
	globalCIPClientRelayStats.h3PrefetchIn.Add(1)
}

func recordCIPClientH3PrefetchOut() {
	if !cipClientRelayStatsEnabled() {
		return
	}
	globalCIPClientRelayStats.h3PrefetchOut.Add(1)
}

func recordCIPClientH2PipeWrite() {
	if !cipClientRelayStatsEnabled() {
		return
	}
	globalCIPClientRelayStats.h2PipeWrite.Add(1)
}

func recordCIPClientH2VisFlush() {
	if !cipClientRelayStatsEnabled() {
		return
	}
	globalCIPClientRelayStats.h2VisFlush.Add(1)
}

func recordCIPClientH2PipeWait(d time.Duration, queueFull bool) {
	if !cipClientRelayStatsEnabled() || d < 0 {
		return
	}
	us := uint64(d.Microseconds())
	if us == 0 && d > 0 {
		us = 1
	}
	globalCIPClientRelayStats.h2PipeWaitUs.Add(us)
	globalCIPClientRelayStats.h2PipeWaitCount.Add(1)
	for {
		cur := globalCIPClientRelayStats.h2PipeWaitUsMax.Load()
		if us <= cur || globalCIPClientRelayStats.h2PipeWaitUsMax.CompareAndSwap(cur, us) {
			break
		}
	}
	if queueFull {
		globalCIPClientRelayStats.h2PipeQueueFull.Add(1)
	}
}

func recordCIPClientS2CPrefetchSojourn(d time.Duration) {
	if !cipClientRelayStatsEnabled() || d < 0 {
		return
	}
	us := uint64(d.Microseconds())
	if us == 0 && d > 0 {
		us = 1
	}
	globalCIPClientRelayStats.s2cPrefetchSojournUs.Add(us)
	globalCIPClientRelayStats.s2cPrefetchSojournCount.Add(1)
	for {
		cur := globalCIPClientRelayStats.s2cPrefetchSojournUsMax.Load()
		if us <= cur || globalCIPClientRelayStats.s2cPrefetchSojournUsMax.CompareAndSwap(cur, us) {
			return
		}
	}
}

func noteCIPClientS2CPrefetchQHigh(depth uint64) {
	if !cipClientRelayStatsEnabled() || depth == 0 {
		return
	}
	for {
		cur := globalCIPClientRelayStats.s2cPrefetchQHigh.Load()
		if depth <= cur || globalCIPClientRelayStats.s2cPrefetchQHigh.CompareAndSwap(cur, depth) {
			return
		}
	}
}

// RecordCIPClientS2CInject records ReadPacket→TUN WritePacket wall time (µs).
func RecordCIPClientS2CInject(d time.Duration) {
	if !cipClientRelayStatsEnabled() || d < 0 {
		return
	}
	us := uint64(d.Microseconds())
	if us == 0 && d > 0 {
		us = 1
	}
	globalCIPClientRelayStats.s2cInjectUs.Add(us)
	globalCIPClientRelayStats.s2cInjectCount.Add(1)
	for {
		cur := globalCIPClientRelayStats.s2cInjectUsMax.Load()
		if us <= cur || globalCIPClientRelayStats.s2cInjectUsMax.CompareAndSwap(cur, us) {
			return
		}
	}
}

// RecordCIPClientAckInjectGap records time between consecutive pure-ACK TUN injects (µs).
func RecordCIPClientAckInjectGap() {
	if !cipClientRelayStatsEnabled() {
		return
	}
	now := time.Now().UnixNano()
	prev := globalCIPClientRelayStats.lastAckInjectNs.Swap(now)
	if prev <= 0 {
		return
	}
	d := time.Duration(now - prev)
	if d < 0 {
		return
	}
	us := uint64(d.Microseconds())
	if us == 0 && d > 0 {
		us = 1
	}
	globalCIPClientRelayStats.ackInjectGapUsTotal.Add(us)
	globalCIPClientRelayStats.ackInjectGapN.Add(1)
	for {
		cur := globalCIPClientRelayStats.ackInjectGapUsMax.Load()
		if us <= cur || globalCIPClientRelayStats.ackInjectGapUsMax.CompareAndSwap(cur, us) {
			return
		}
	}
}

// LogCIPClientRelayStats emits RESULT_CONNECT_IP_CLIENT_STATS for field scrapers.
func LogCIPClientRelayStats(tag string) {
	if !cipClientRelayStatsEnabled() {
		return
	}
	s := SnapshotCIPClientRelayStats()
	avgWait := uint64(0)
	if s.H2PipeWaitCount > 0 {
		avgWait = s.H2PipeWaitUsTotal / s.H2PipeWaitCount
	}
	avgPrefetch := uint64(0)
	if s.S2CPrefetchSojournCount > 0 {
		avgPrefetch = s.S2CPrefetchSojournUsTotal / s.S2CPrefetchSojournCount
	}
	avgInject := uint64(0)
	if s.S2CInjectCount > 0 {
		avgInject = s.S2CInjectUsTotal / s.S2CInjectCount
	}
	avgAckGap := uint64(0)
	if s.AckInjectGapN > 0 {
		avgAckGap = s.AckInjectGapUsTotal / s.AckInjectGapN
	}
	avgWriteGap := uint64(0)
	if s.C2SWriteGapN > 0 {
		avgWriteGap = s.C2SWriteGapUsTotal / s.C2SWriteGapN
	}
	log.Printf(
		"RESULT_CONNECT_IP_CLIENT_STATS tag=%s write_ok=%d write_fail=%d write_bytes=%d flush=%d ingress_drops=%d h3_prefetch_in=%d h3_prefetch_out=%d h2_pipe_write=%d h2_vis_flush=%d h2_pipe_wait_us_avg=%d h2_pipe_wait_us_max=%d h2_pipe_wait_n=%d h2_pipe_q_full=%d s2c_prefetch_sojourn_us_avg=%d s2c_prefetch_sojourn_us_max=%d s2c_prefetch_sojourn_n=%d s2c_prefetch_q_high=%d s2c_inject_us_avg=%d s2c_inject_us_max=%d s2c_inject_n=%d ack_inject_gap_us_avg=%d ack_inject_gap_us_max=%d ack_inject_gap_n=%d c2s_write_gap_us_avg=%d c2s_write_gap_us_max=%d c2s_write_gap_n=%d c2s_write_gap_gt_1ms=%d c2s_write_gap_gt_5ms=%d",
		tag,
		s.WriteOK,
		s.WriteFail,
		s.WriteBytes,
		s.Flush,
		s.IngressDrops,
		s.H3PrefetchIn,
		s.H3PrefetchOut,
		s.H2PipeWrite,
		s.H2VisFlush,
		avgWait,
		s.H2PipeWaitUsMax,
		s.H2PipeWaitCount,
		s.H2PipeQueueFull,
		avgPrefetch,
		s.S2CPrefetchSojournUsMax,
		s.S2CPrefetchSojournCount,
		s.S2CPrefetchQHigh,
		avgInject,
		s.S2CInjectUsMax,
		s.S2CInjectCount,
		avgAckGap,
		s.AckInjectGapUsMax,
		s.AckInjectGapN,
		avgWriteGap,
		s.C2SWriteGapUsMax,
		s.C2SWriteGapN,
		s.C2SWriteGapGt1ms,
		s.C2SWriteGapGt5ms,
	)
}

func writeCIPClientRelayStatsFile(tag string) {
	s := SnapshotCIPClientRelayStats()
	avgWait := uint64(0)
	if s.H2PipeWaitCount > 0 {
		avgWait = s.H2PipeWaitUsTotal / s.H2PipeWaitCount
	}
	avgPrefetch := uint64(0)
	if s.S2CPrefetchSojournCount > 0 {
		avgPrefetch = s.S2CPrefetchSojournUsTotal / s.S2CPrefetchSojournCount
	}
	avgInject := uint64(0)
	if s.S2CInjectCount > 0 {
		avgInject = s.S2CInjectUsTotal / s.S2CInjectCount
	}
	avgAckGap := uint64(0)
	if s.AckInjectGapN > 0 {
		avgAckGap = s.AckInjectGapUsTotal / s.AckInjectGapN
	}
	avgWriteGap := uint64(0)
	if s.C2SWriteGapN > 0 {
		avgWriteGap = s.C2SWriteGapUsTotal / s.C2SWriteGapN
	}
	type dump struct {
		Tag                       string `json:"tag"`
		WriteOK                   uint64 `json:"write_ok"`
		WriteFail                 uint64 `json:"write_fail"`
		WriteBytes                uint64 `json:"write_bytes"`
		Flush                     uint64 `json:"flush"`
		IngressDrops              uint64 `json:"ingress_drops"`
		H3PrefetchIn              uint64 `json:"h3_prefetch_in"`
		H3PrefetchOut             uint64 `json:"h3_prefetch_out"`
		H2PipeWrite               uint64 `json:"h2_pipe_write"`
		H2VisFlush                uint64 `json:"h2_vis_flush"`
		H2PipeWaitUsAvg           uint64 `json:"h2_pipe_wait_us_avg"`
		H2PipeWaitUsMax           uint64 `json:"h2_pipe_wait_us_max"`
		H2PipeWaitN               uint64 `json:"h2_pipe_wait_n"`
		H2PipeQueueFull           uint64 `json:"h2_pipe_q_full"`
		S2CPrefetchSojournUsAvg   uint64 `json:"s2c_prefetch_sojourn_us_avg"`
		S2CPrefetchSojournUsMax   uint64 `json:"s2c_prefetch_sojourn_us_max"`
		S2CPrefetchSojournN       uint64 `json:"s2c_prefetch_sojourn_n"`
		S2CPrefetchQHigh          uint64 `json:"s2c_prefetch_q_high"`
		S2CInjectUsAvg            uint64 `json:"s2c_inject_us_avg"`
		S2CInjectUsMax            uint64 `json:"s2c_inject_us_max"`
		S2CInjectN                uint64 `json:"s2c_inject_n"`
		AckInjectGapUsAvg         uint64 `json:"ack_inject_gap_us_avg"`
		AckInjectGapUsMax         uint64 `json:"ack_inject_gap_us_max"`
		AckInjectGapN             uint64 `json:"ack_inject_gap_n"`
		C2SWriteGapUsAvg          uint64 `json:"c2s_write_gap_us_avg"`
		C2SWriteGapUsMax          uint64 `json:"c2s_write_gap_us_max"`
		C2SWriteGapN              uint64 `json:"c2s_write_gap_n"`
		C2SWriteGapGt1ms          uint64 `json:"c2s_write_gap_gt_1ms"`
		C2SWriteGapGt5ms          uint64 `json:"c2s_write_gap_gt_5ms"`
		TsUnixMs                  int64  `json:"ts_unix_ms"`
	}
	d := dump{
		Tag:                     tag,
		WriteOK:                 s.WriteOK,
		WriteFail:               s.WriteFail,
		WriteBytes:              s.WriteBytes,
		Flush:                   s.Flush,
		IngressDrops:            s.IngressDrops,
		H3PrefetchIn:            s.H3PrefetchIn,
		H3PrefetchOut:           s.H3PrefetchOut,
		H2PipeWrite:             s.H2PipeWrite,
		H2VisFlush:              s.H2VisFlush,
		H2PipeWaitUsAvg:         avgWait,
		H2PipeWaitUsMax:         s.H2PipeWaitUsMax,
		H2PipeWaitN:             s.H2PipeWaitCount,
		H2PipeQueueFull:         s.H2PipeQueueFull,
		S2CPrefetchSojournUsAvg: avgPrefetch,
		S2CPrefetchSojournUsMax: s.S2CPrefetchSojournUsMax,
		S2CPrefetchSojournN:     s.S2CPrefetchSojournCount,
		S2CPrefetchQHigh:        s.S2CPrefetchQHigh,
		S2CInjectUsAvg:          avgInject,
		S2CInjectUsMax:          s.S2CInjectUsMax,
		S2CInjectN:              s.S2CInjectCount,
		AckInjectGapUsAvg:       avgAckGap,
		AckInjectGapUsMax:       s.AckInjectGapUsMax,
		AckInjectGapN:           s.AckInjectGapN,
		C2SWriteGapUsAvg:        avgWriteGap,
		C2SWriteGapUsMax:        s.C2SWriteGapUsMax,
		C2SWriteGapN:            s.C2SWriteGapN,
		C2SWriteGapGt1ms:        s.C2SWriteGapGt1ms,
		C2SWriteGapGt5ms:        s.C2SWriteGapGt5ms,
		TsUnixMs:                time.Now().UnixMilli(),
	}
	raw, err := json.Marshal(d)
	if err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(os.TempDir(), "masque-connect-ip-client-stats.json"), raw, 0o644)
}
