// Package relaystats provides field/bench CONNECT-IP C2S/S2C counters
// (MASQUE_CONNECT_IP_RELAY_STATS=1 → RESULT_CONNECT_IP_RELAY_STATS), mirroring
// CONNECT-UDP MASQUE_UDP_RELAY_STATS.
package relaystats

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
		EnableForBench()
	}
}

// Snapshot is a point-in-time CONNECT-IP relay counter set (server S2 path + plane).
type Snapshot struct {
	C2SPlaneIn       uint64 // packets ReadPacket from CONNECT-IP plane (client→server)
	C2SPlaneBytes    uint64
	S2CEnqueue       uint64 // downloadCh / writeCh enqueues toward client
	S2COut           uint64 // successful WritePacket toward client
	S2COutBytes      uint64
	S2CWriteFail     uint64
	S2CBatchFlush    uint64
	S2CRTORetransmit uint64
	S2CAckAdmitDrop  uint64 // pure ACK dropped under writeCh pressure (cumulative supersede)
	DownloadQHigh    uint64 // peak downloadCh depth observed
	WriteQHigh       uint64 // peak writeCh depth observed
	S2CFlushUsTotal  uint64 // Σ FlushOutgoingDatagramSend wall time (µs)
	S2CFlushUsMax    uint64
	AckSojournUsTotal uint64 // Σ writeCh ACK enqueue→dequeue (µs)
	AckSojournUsMax   uint64
	AckSojournN       uint64
	C2SSilence        uint64 // C2S queue full → no rcvNxt / no nested ACK
	C2SQueueHigh      uint64 // peak c2sCh depth
	OnwardFlushUsTotal uint64 // Σ outbound.Flush wall (µs) toward host TCP
	OnwardFlushUsMax   uint64
	OnwardFlushN       uint64
	AckAcceptToEnqUsTotal uint64 // Σ first-accept-in-window → sendAck* (µs)
	AckAcceptToEnqUsMax   uint64
	AckAcceptToEnqN       uint64
	AckFlushGapUsTotal    uint64 // Σ inter-ACK Flush gaps (µs)
	AckFlushGapUsMax      uint64
	AckFlushGapN          uint64
	C2SPlaneGapUsTotal    uint64 // Σ inter-C2S plane packet gaps (µs)
	C2SPlaneGapUsMax      uint64
	C2SPlaneGapN          uint64
	C2SPlaneGapGt1ms      uint64 // gaps > 1ms
	C2SPlaneGapGt5ms      uint64 // gaps > 5ms
}

type stats struct {
	c2sPlaneIn       atomic.Uint64
	c2sPlaneBytes    atomic.Uint64
	s2cEnqueue       atomic.Uint64
	s2cOut           atomic.Uint64
	s2cOutBytes      atomic.Uint64
	s2cWriteFail     atomic.Uint64
	s2cBatchFlush    atomic.Uint64
	s2cRTORetransmit atomic.Uint64
	s2cAckAdmitDrop  atomic.Uint64
	downloadQHigh    atomic.Uint64
	writeQHigh       atomic.Uint64
	s2cFlushUsTotal  atomic.Uint64
	s2cFlushUsMax    atomic.Uint64
	ackSojournUsTotal atomic.Uint64
	ackSojournUsMax   atomic.Uint64
	ackSojournN       atomic.Uint64
	c2sSilence        atomic.Uint64
	c2sQueueHigh      atomic.Uint64
	onwardFlushUsTotal atomic.Uint64
	onwardFlushUsMax   atomic.Uint64
	onwardFlushN       atomic.Uint64
	ackAcceptToEnqUsTotal atomic.Uint64
	ackAcceptToEnqUsMax   atomic.Uint64
	ackAcceptToEnqN       atomic.Uint64
	ackFlushGapUsTotal    atomic.Uint64
	ackFlushGapUsMax      atomic.Uint64
	ackFlushGapN          atomic.Uint64
	c2sPlaneGapUsTotal    atomic.Uint64
	c2sPlaneGapUsMax      atomic.Uint64
	c2sPlaneGapN          atomic.Uint64
	c2sPlaneGapGt1ms      atomic.Uint64
	c2sPlaneGapGt5ms      atomic.Uint64
	lastC2SPlaneNs        atomic.Int64
}

var global stats
var active atomic.Bool

func enabled() bool { return active.Load() }

// EnableForBench turns on CIP relay counters (tests / field env).
func EnableForBench() { active.Store(true) }

// Reset clears process-wide counters (bench isolation).
func Reset() {
	global.c2sPlaneIn.Store(0)
	global.c2sPlaneBytes.Store(0)
	global.s2cEnqueue.Store(0)
	global.s2cOut.Store(0)
	global.s2cOutBytes.Store(0)
	global.s2cWriteFail.Store(0)
	global.s2cBatchFlush.Store(0)
	global.s2cRTORetransmit.Store(0)
	global.s2cAckAdmitDrop.Store(0)
	global.downloadQHigh.Store(0)
	global.writeQHigh.Store(0)
	global.s2cFlushUsTotal.Store(0)
	global.s2cFlushUsMax.Store(0)
	global.ackSojournUsTotal.Store(0)
	global.ackSojournUsMax.Store(0)
	global.ackSojournN.Store(0)
	global.c2sSilence.Store(0)
	global.c2sQueueHigh.Store(0)
	global.onwardFlushUsTotal.Store(0)
	global.onwardFlushUsMax.Store(0)
	global.onwardFlushN.Store(0)
	global.ackAcceptToEnqUsTotal.Store(0)
	global.ackAcceptToEnqUsMax.Store(0)
	global.ackAcceptToEnqN.Store(0)
	global.ackFlushGapUsTotal.Store(0)
	global.ackFlushGapUsMax.Store(0)
	global.ackFlushGapN.Store(0)
	global.c2sPlaneGapUsTotal.Store(0)
	global.c2sPlaneGapUsMax.Store(0)
	global.c2sPlaneGapN.Store(0)
	global.c2sPlaneGapGt1ms.Store(0)
	global.c2sPlaneGapGt5ms.Store(0)
	global.lastC2SPlaneNs.Store(0)
}

// SnapshotNow returns current counters.
func SnapshotNow() Snapshot {
	return Snapshot{
		C2SPlaneIn:       global.c2sPlaneIn.Load(),
		C2SPlaneBytes:    global.c2sPlaneBytes.Load(),
		S2CEnqueue:       global.s2cEnqueue.Load(),
		S2COut:           global.s2cOut.Load(),
		S2COutBytes:      global.s2cOutBytes.Load(),
		S2CWriteFail:     global.s2cWriteFail.Load(),
		S2CBatchFlush:    global.s2cBatchFlush.Load(),
		S2CRTORetransmit: global.s2cRTORetransmit.Load(),
		S2CAckAdmitDrop:  global.s2cAckAdmitDrop.Load(),
		DownloadQHigh:    global.downloadQHigh.Load(),
		WriteQHigh:       global.writeQHigh.Load(),
		S2CFlushUsTotal:   global.s2cFlushUsTotal.Load(),
		S2CFlushUsMax:     global.s2cFlushUsMax.Load(),
		AckSojournUsTotal:  global.ackSojournUsTotal.Load(),
		AckSojournUsMax:    global.ackSojournUsMax.Load(),
		AckSojournN:        global.ackSojournN.Load(),
		C2SSilence:         global.c2sSilence.Load(),
		C2SQueueHigh:       global.c2sQueueHigh.Load(),
		OnwardFlushUsTotal:    global.onwardFlushUsTotal.Load(),
		OnwardFlushUsMax:      global.onwardFlushUsMax.Load(),
		OnwardFlushN:          global.onwardFlushN.Load(),
		AckAcceptToEnqUsTotal: global.ackAcceptToEnqUsTotal.Load(),
		AckAcceptToEnqUsMax:   global.ackAcceptToEnqUsMax.Load(),
		AckAcceptToEnqN:       global.ackAcceptToEnqN.Load(),
		AckFlushGapUsTotal:    global.ackFlushGapUsTotal.Load(),
		AckFlushGapUsMax:      global.ackFlushGapUsMax.Load(),
		AckFlushGapN:          global.ackFlushGapN.Load(),
		C2SPlaneGapUsTotal:    global.c2sPlaneGapUsTotal.Load(),
		C2SPlaneGapUsMax:      global.c2sPlaneGapUsMax.Load(),
		C2SPlaneGapN:          global.c2sPlaneGapN.Load(),
		C2SPlaneGapGt1ms:      global.c2sPlaneGapGt1ms.Load(),
		C2SPlaneGapGt5ms:      global.c2sPlaneGapGt5ms.Load(),
	}
}

// BeginSession resets counters and emits RESULT_CONNECT_IP_RELAY_STATS ~2 Hz until end().
func BeginSession(tag string) (end func()) {
	if !enabled() {
		return func() {}
	}
	Reset()
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
				Log(tag)
				writeFile(tag)
			}
		}
	}()
	return func() {
		close(stop)
		<-done
		Log(tag)
		writeFile(tag)
	}
}

func writeFile(tag string) {
	s := SnapshotNow()
	type dump struct {
		Tag              string `json:"tag"`
		C2SPlaneIn       uint64 `json:"c2s_plane_in"`
		C2SPlaneBytes    uint64 `json:"c2s_plane_bytes"`
		S2CEnqueue       uint64 `json:"s2c_enqueue"`
		S2COut           uint64 `json:"s2c_out"`
		S2COutBytes      uint64 `json:"s2c_out_bytes"`
		S2CWriteFail     uint64 `json:"s2c_write_fail"`
		S2CBatchFlush    uint64 `json:"s2c_batch_flush"`
		S2CRTORetransmit uint64 `json:"s2c_rto_retransmit"`
		S2CAckAdmitDrop  uint64 `json:"s2c_ack_admit_drop"`
		DownloadQHigh    uint64 `json:"download_q_high"`
		WriteQHigh       uint64 `json:"write_q_high"`
		S2CFlushUsAvg     uint64 `json:"s2c_flush_us_avg"`
		S2CFlushUsMax     uint64 `json:"s2c_flush_us_max"`
		AckSojournUsAvg    uint64 `json:"ack_sojourn_us_avg"`
		AckSojournUsMax    uint64 `json:"ack_sojourn_us_max"`
		AckSojournN        uint64 `json:"ack_sojourn_n"`
		C2SSilence         uint64 `json:"c2s_silence"`
		C2SQueueHigh       uint64 `json:"c2s_q_high"`
		OnwardFlushUsAvg      uint64 `json:"onward_flush_us_avg"`
		OnwardFlushUsMax      uint64 `json:"onward_flush_us_max"`
		OnwardFlushN          uint64 `json:"onward_flush_n"`
		AckAcceptToEnqUsAvg   uint64 `json:"ack_accept_to_enq_us_avg"`
		AckAcceptToEnqUsMax   uint64 `json:"ack_accept_to_enq_us_max"`
		AckAcceptToEnqN       uint64 `json:"ack_accept_to_enq_n"`
		AckFlushGapUsAvg      uint64 `json:"ack_flush_gap_us_avg"`
		AckFlushGapUsMax      uint64 `json:"ack_flush_gap_us_max"`
		AckFlushGapN          uint64 `json:"ack_flush_gap_n"`
		C2SPlaneGapUsAvg      uint64 `json:"c2s_plane_gap_us_avg"`
		C2SPlaneGapUsMax      uint64 `json:"c2s_plane_gap_us_max"`
		C2SPlaneGapN          uint64 `json:"c2s_plane_gap_n"`
		C2SPlaneGapGt1ms      uint64 `json:"c2s_plane_gap_gt_1ms"`
		C2SPlaneGapGt5ms      uint64 `json:"c2s_plane_gap_gt_5ms"`
		TsUnixMs              int64  `json:"ts_unix_ms"`
	}
	flushAvg := uint64(0)
	if s.S2CBatchFlush > 0 {
		flushAvg = s.S2CFlushUsTotal / s.S2CBatchFlush
	}
	sojournAvg := uint64(0)
	if s.AckSojournN > 0 {
		sojournAvg = s.AckSojournUsTotal / s.AckSojournN
	}
	onwardAvg := uint64(0)
	if s.OnwardFlushN > 0 {
		onwardAvg = s.OnwardFlushUsTotal / s.OnwardFlushN
	}
	acceptAvg := uint64(0)
	if s.AckAcceptToEnqN > 0 {
		acceptAvg = s.AckAcceptToEnqUsTotal / s.AckAcceptToEnqN
	}
	gapAvg := uint64(0)
	if s.AckFlushGapN > 0 {
		gapAvg = s.AckFlushGapUsTotal / s.AckFlushGapN
	}
	planeGapAvg := uint64(0)
	if s.C2SPlaneGapN > 0 {
		planeGapAvg = s.C2SPlaneGapUsTotal / s.C2SPlaneGapN
	}
	d := dump{
		Tag:                 tag,
		C2SPlaneIn:          s.C2SPlaneIn,
		C2SPlaneBytes:       s.C2SPlaneBytes,
		S2CEnqueue:          s.S2CEnqueue,
		S2COut:              s.S2COut,
		S2COutBytes:         s.S2COutBytes,
		S2CWriteFail:        s.S2CWriteFail,
		S2CBatchFlush:       s.S2CBatchFlush,
		S2CRTORetransmit:    s.S2CRTORetransmit,
		S2CAckAdmitDrop:     s.S2CAckAdmitDrop,
		DownloadQHigh:       s.DownloadQHigh,
		WriteQHigh:          s.WriteQHigh,
		S2CFlushUsAvg:       flushAvg,
		S2CFlushUsMax:       s.S2CFlushUsMax,
		AckSojournUsAvg:     sojournAvg,
		AckSojournUsMax:     s.AckSojournUsMax,
		AckSojournN:         s.AckSojournN,
		C2SSilence:          s.C2SSilence,
		C2SQueueHigh:        s.C2SQueueHigh,
		OnwardFlushUsAvg:    onwardAvg,
		OnwardFlushUsMax:    s.OnwardFlushUsMax,
		OnwardFlushN:        s.OnwardFlushN,
		AckAcceptToEnqUsAvg: acceptAvg,
		AckAcceptToEnqUsMax: s.AckAcceptToEnqUsMax,
		AckAcceptToEnqN:     s.AckAcceptToEnqN,
		AckFlushGapUsAvg:    gapAvg,
		AckFlushGapUsMax:    s.AckFlushGapUsMax,
		AckFlushGapN:        s.AckFlushGapN,
		C2SPlaneGapUsAvg:    planeGapAvg,
		C2SPlaneGapUsMax:    s.C2SPlaneGapUsMax,
		C2SPlaneGapN:        s.C2SPlaneGapN,
		C2SPlaneGapGt1ms:    s.C2SPlaneGapGt1ms,
		C2SPlaneGapGt5ms:    s.C2SPlaneGapGt5ms,
		TsUnixMs:            time.Now().UnixMilli(),
	}
	raw, err := json.Marshal(d)
	if err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(os.TempDir(), "masque-connect-ip-relay-stats.json"), raw, 0o644)
}

// Log emits a machine-parseable bench line.
func Log(tag string) {
	if !enabled() {
		return
	}
	s := SnapshotNow()
	flushAvg := uint64(0)
	if s.S2CBatchFlush > 0 {
		flushAvg = s.S2CFlushUsTotal / s.S2CBatchFlush
	}
	sojournAvg := uint64(0)
	if s.AckSojournN > 0 {
		sojournAvg = s.AckSojournUsTotal / s.AckSojournN
	}
	onwardAvg := uint64(0)
	if s.OnwardFlushN > 0 {
		onwardAvg = s.OnwardFlushUsTotal / s.OnwardFlushN
	}
	acceptAvg := uint64(0)
	if s.AckAcceptToEnqN > 0 {
		acceptAvg = s.AckAcceptToEnqUsTotal / s.AckAcceptToEnqN
	}
	gapAvg := uint64(0)
	if s.AckFlushGapN > 0 {
		gapAvg = s.AckFlushGapUsTotal / s.AckFlushGapN
	}
	planeGapAvg := uint64(0)
	if s.C2SPlaneGapN > 0 {
		planeGapAvg = s.C2SPlaneGapUsTotal / s.C2SPlaneGapN
	}
	log.Printf(
		"RESULT_CONNECT_IP_RELAY_STATS tag=%s c2s_plane_in=%d c2s_plane_bytes=%d s2c_enqueue=%d s2c_out=%d s2c_out_bytes=%d s2c_write_fail=%d s2c_batch_flush=%d s2c_rto_retransmit=%d s2c_ack_admit_drop=%d download_q_high=%d write_q_high=%d s2c_flush_us_avg=%d s2c_flush_us_max=%d ack_sojourn_us_avg=%d ack_sojourn_us_max=%d ack_sojourn_n=%d c2s_silence=%d c2s_q_high=%d onward_flush_us_avg=%d onward_flush_us_max=%d onward_flush_n=%d ack_accept_to_enq_us_avg=%d ack_accept_to_enq_us_max=%d ack_accept_to_enq_n=%d ack_flush_gap_us_avg=%d ack_flush_gap_us_max=%d ack_flush_gap_n=%d c2s_plane_gap_us_avg=%d c2s_plane_gap_us_max=%d c2s_plane_gap_n=%d c2s_plane_gap_gt_1ms=%d c2s_plane_gap_gt_5ms=%d",
		tag,
		s.C2SPlaneIn,
		s.C2SPlaneBytes,
		s.S2CEnqueue,
		s.S2COut,
		s.S2COutBytes,
		s.S2CWriteFail,
		s.S2CBatchFlush,
		s.S2CRTORetransmit,
		s.S2CAckAdmitDrop,
		s.DownloadQHigh,
		s.WriteQHigh,
		flushAvg,
		s.S2CFlushUsMax,
		sojournAvg,
		s.AckSojournUsMax,
		s.AckSojournN,
		s.C2SSilence,
		s.C2SQueueHigh,
		onwardAvg,
		s.OnwardFlushUsMax,
		s.OnwardFlushN,
		acceptAvg,
		s.AckAcceptToEnqUsMax,
		s.AckAcceptToEnqN,
		gapAvg,
		s.AckFlushGapUsMax,
		s.AckFlushGapN,
		planeGapAvg,
		s.C2SPlaneGapUsMax,
		s.C2SPlaneGapN,
		s.C2SPlaneGapGt1ms,
		s.C2SPlaneGapGt5ms,
	)
}

// RecordC2SPlaneIn records one packet read from the CONNECT-IP plane (client→server).
func RecordC2SPlaneIn(nBytes int) {
	if !enabled() || nBytes <= 0 {
		return
	}
	global.c2sPlaneIn.Add(1)
	global.c2sPlaneBytes.Add(uint64(nBytes))
	now := time.Now().UnixNano()
	prev := global.lastC2SPlaneNs.Swap(now)
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
	global.c2sPlaneGapUsTotal.Add(us)
	global.c2sPlaneGapN.Add(1)
	if us > 1000 {
		global.c2sPlaneGapGt1ms.Add(1)
	}
	if us > 5000 {
		global.c2sPlaneGapGt5ms.Add(1)
	}
	for {
		cur := global.c2sPlaneGapUsMax.Load()
		if us <= cur || global.c2sPlaneGapUsMax.CompareAndSwap(cur, us) {
			return
		}
	}
}

// RecordS2CEnqueue records one segment queued toward the client.
func RecordS2CEnqueue() {
	if enabled() {
		global.s2cEnqueue.Add(1)
	}
}

// RecordS2COut records a successful plane write toward the client.
func RecordS2COut(nBytes int) {
	if !enabled() {
		return
	}
	global.s2cOut.Add(1)
	if nBytes > 0 {
		global.s2cOutBytes.Add(uint64(nBytes))
	}
}

// RecordS2CWriteFail records a failed WritePacket toward the client.
func RecordS2CWriteFail() {
	if enabled() {
		global.s2cWriteFail.Add(1)
	}
}

// RecordS2CBatchFlush records one Fountain/coalesced flush toward the client.
func RecordS2CBatchFlush() {
	if enabled() {
		global.s2cBatchFlush.Add(1)
	}
}

// RecordS2CFlushDuration records wall time of one FlushOutgoingDatagramSend (µs).
func RecordS2CFlushDuration(d time.Duration) {
	if !enabled() || d < 0 {
		return
	}
	us := uint64(d.Microseconds())
	if us == 0 && d > 0 {
		us = 1
	}
	global.s2cFlushUsTotal.Add(us)
	for {
		cur := global.s2cFlushUsMax.Load()
		if us <= cur || global.s2cFlushUsMax.CompareAndSwap(cur, us) {
			return
		}
	}
}

// RecordS2CAckSojourn records writeCh ACK enqueue→dequeue wait (µs).
func RecordS2CAckSojourn(d time.Duration) {
	if !enabled() || d < 0 {
		return
	}
	us := uint64(d.Microseconds())
	if us == 0 && d > 0 {
		us = 1
	}
	global.ackSojournUsTotal.Add(us)
	global.ackSojournN.Add(1)
	for {
		cur := global.ackSojournUsMax.Load()
		if us <= cur || global.ackSojournUsMax.CompareAndSwap(cur, us) {
			return
		}
	}
}

// RecordC2SSilence records one C2S backpressure silence (no nested ACK).
func RecordC2SSilence() {
	if enabled() {
		global.c2sSilence.Add(1)
	}
}

// NoteC2SQueueHigh updates peak c2sCh depth.
func NoteC2SQueueHigh(depth uint64) {
	if !enabled() || depth == 0 {
		return
	}
	for {
		cur := global.c2sQueueHigh.Load()
		if depth <= cur || global.c2sQueueHigh.CompareAndSwap(cur, depth) {
			return
		}
	}
}

// RecordOnwardFlushDuration records wall time of one host-TCP bufio.Flush (µs).
func RecordOnwardFlushDuration(d time.Duration) {
	if !enabled() || d < 0 {
		return
	}
	us := uint64(d.Microseconds())
	if us == 0 && d > 0 {
		us = 1
	}
	global.onwardFlushUsTotal.Add(us)
	global.onwardFlushN.Add(1)
	for {
		cur := global.onwardFlushUsMax.Load()
		if us <= cur || global.onwardFlushUsMax.CompareAndSwap(cur, us) {
			return
		}
	}
}

// RecordAckAcceptToEnq records first-accept-in-ACK-window → sendAck* (µs).
func RecordAckAcceptToEnq(d time.Duration) {
	if !enabled() || d < 0 {
		return
	}
	us := uint64(d.Microseconds())
	if us == 0 && d > 0 {
		us = 1
	}
	global.ackAcceptToEnqUsTotal.Add(us)
	global.ackAcceptToEnqN.Add(1)
	for {
		cur := global.ackAcceptToEnqUsMax.Load()
		if us <= cur || global.ackAcceptToEnqUsMax.CompareAndSwap(cur, us) {
			return
		}
	}
}

// RecordAckFlushGap records time between consecutive ACK-path S2C Flushes (µs).
func RecordAckFlushGap(d time.Duration) {
	if !enabled() || d < 0 {
		return
	}
	us := uint64(d.Microseconds())
	if us == 0 && d > 0 {
		us = 1
	}
	global.ackFlushGapUsTotal.Add(us)
	global.ackFlushGapN.Add(1)
	for {
		cur := global.ackFlushGapUsMax.Load()
		if us <= cur || global.ackFlushGapUsMax.CompareAndSwap(cur, us) {
			return
		}
	}
}

// RecordS2CRTORetransmit records one S2C RTO head-MSS retransmit.
func RecordS2CRTORetransmit() {
	if enabled() {
		global.s2cRTORetransmit.Add(1)
	}
}

// RecordS2CAckAdmitDrop records a pure ACK dropped under writeCh pressure
// (cumulative ACK supersede — safe; avoids demux HOL under iperf -P≥3 upload).
func RecordS2CAckAdmitDrop() {
	if enabled() {
		global.s2cAckAdmitDrop.Add(1)
	}
}

// NoteDownloadQHigh updates peak downloadCh depth.
func NoteDownloadQHigh(depth uint64) {
	if !enabled() || depth == 0 {
		return
	}
	for {
		cur := global.downloadQHigh.Load()
		if depth <= cur || global.downloadQHigh.CompareAndSwap(cur, depth) {
			return
		}
	}
}

// NoteWriteQHigh updates peak writeCh depth.
func NoteWriteQHigh(depth uint64) {
	if !enabled() || depth == 0 {
		return
	}
	for {
		cur := global.writeQHigh.Load()
		if depth <= cur || global.writeQHigh.CompareAndSwap(cur, depth) {
			return
		}
	}
}
