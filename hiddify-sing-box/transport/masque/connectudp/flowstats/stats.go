// Package flowstats holds CONNECT-UDP client/server flow counters for bench attribution.
// Enable with MASQUE_UDP_RELAY_STATS=1 (same env as server relay stats).
package flowstats

import (
	"log"
	"os"
	"strings"
	"sync/atomic"
)

var (
	active atomic.Bool

	clientC2SWriteOK        atomic.Uint64
	clientC2SWriteFail      atomic.Uint64
	clientC2STransientRetry atomic.Uint64
	clientC2SOversize       atomic.Uint64
)

func init() {
	v := strings.TrimSpace(os.Getenv("MASQUE_UDP_RELAY_STATS"))
	if v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes") {
		Enable()
	}
}

// Enable turns on client flow counters (bench / field attribution).
func Enable() {
	active.Store(true)
}

func enabled() bool { return active.Load() }

// RecordClientC2SOK increments successful client→server datagram write.
func RecordClientC2SOK() {
	if enabled() {
		clientC2SWriteOK.Add(1)
	}
}

// RecordClientC2SFail increments failed client WriteTo / SendDatagram / capsule flush.
func RecordClientC2SFail() {
	if enabled() {
		clientC2SWriteFail.Add(1)
	}
}

// RecordClientC2STransientRetry counts QUIC/TCP transient backpressure spins that later succeeded or failed.
func RecordClientC2STransientRetry() {
	if enabled() {
		clientC2STransientRetry.Add(1)
	}
}

// RecordClientC2SOversize counts local rejects for oversize payloads before wire send.
func RecordClientC2SOversize() {
	if enabled() {
		clientC2SOversize.Add(1)
	}
}

// Reset clears client counters (bench isolation between probes).
func Reset() {
	clientC2SWriteOK.Store(0)
	clientC2SWriteFail.Store(0)
	clientC2STransientRetry.Store(0)
	clientC2SOversize.Store(0)
}

// Snapshot is a point-in-time client C2S counter set.
type Snapshot struct {
	C2SWriteOK        uint64
	C2SWriteFail      uint64
	C2STransientRetry uint64
	C2SOversize       uint64
}

// TakeSnapshot returns current client counters.
func TakeSnapshot() Snapshot {
	return Snapshot{
		C2SWriteOK:        clientC2SWriteOK.Load(),
		C2SWriteFail:      clientC2SWriteFail.Load(),
		C2STransientRetry: clientC2STransientRetry.Load(),
		C2SOversize:       clientC2SOversize.Load(),
	}
}

// Detail is Close-time wire/pipe visibility for loss attribution (write_ok can lead wire).
type Detail struct {
	WireSentBytes      int64
	WireCommittedBytes int64
	PipeBufferedBytes  int
}

// LogClientStats emits RESULT_CLIENT_UDP_STATS for bench parsers.
func LogClientStats(tag string) {
	LogClientStatsDetailed(tag, Detail{})
}

// LogClientStatsDetailed emits RESULT_CLIENT_UDP_STATS plus wire/pipe depth fields.
func LogClientStatsDetailed(tag string, d Detail) {
	if !enabled() {
		return
	}
	s := TakeSnapshot()
	log.Printf(
		"RESULT_CLIENT_UDP_STATS tag=%s c2s_write_ok=%d c2s_write_fail=%d c2s_transient_retry=%d c2s_oversize=%d wire_sent=%d wire_committed=%d pipe_buf=%d",
		tag,
		s.C2SWriteOK,
		s.C2SWriteFail,
		s.C2STransientRetry,
		s.C2SOversize,
		d.WireSentBytes,
		d.WireCommittedBytes,
		d.PipeBufferedBytes,
	)
}
