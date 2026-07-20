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
	DownloadQHigh    uint64 // peak downloadCh depth observed
	WriteQHigh       uint64 // peak writeCh depth observed
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
	downloadQHigh    atomic.Uint64
	writeQHigh       atomic.Uint64
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
	global.downloadQHigh.Store(0)
	global.writeQHigh.Store(0)
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
		DownloadQHigh:    global.downloadQHigh.Load(),
		WriteQHigh:       global.writeQHigh.Load(),
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
		DownloadQHigh    uint64 `json:"download_q_high"`
		WriteQHigh       uint64 `json:"write_q_high"`
		TsUnixMs         int64  `json:"ts_unix_ms"`
	}
	d := dump{
		Tag:              tag,
		C2SPlaneIn:       s.C2SPlaneIn,
		C2SPlaneBytes:    s.C2SPlaneBytes,
		S2CEnqueue:       s.S2CEnqueue,
		S2COut:           s.S2COut,
		S2COutBytes:      s.S2COutBytes,
		S2CWriteFail:     s.S2CWriteFail,
		S2CBatchFlush:    s.S2CBatchFlush,
		S2CRTORetransmit: s.S2CRTORetransmit,
		DownloadQHigh:    s.DownloadQHigh,
		WriteQHigh:       s.WriteQHigh,
		TsUnixMs:         time.Now().UnixMilli(),
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
	log.Printf(
		"RESULT_CONNECT_IP_RELAY_STATS tag=%s c2s_plane_in=%d c2s_plane_bytes=%d s2c_enqueue=%d s2c_out=%d s2c_out_bytes=%d s2c_write_fail=%d s2c_batch_flush=%d s2c_rto_retransmit=%d download_q_high=%d write_q_high=%d",
		tag,
		s.C2SPlaneIn,
		s.C2SPlaneBytes,
		s.S2CEnqueue,
		s.S2COut,
		s.S2COutBytes,
		s.S2CWriteFail,
		s.S2CBatchFlush,
		s.S2CRTORetransmit,
		s.DownloadQHigh,
		s.WriteQHigh,
	)
}

// RecordC2SPlaneIn records one packet read from the CONNECT-IP plane (client→server).
func RecordC2SPlaneIn(nBytes int) {
	if !enabled() || nBytes <= 0 {
		return
	}
	global.c2sPlaneIn.Add(1)
	global.c2sPlaneBytes.Add(uint64(nBytes))
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

// RecordS2CRTORetransmit records one S2C RTO head-MSS retransmit.
func RecordS2CRTORetransmit() {
	if enabled() {
		global.s2cRTORetransmit.Add(1)
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
