package relay

import (
	"log"
	"os"
	"sync/atomic"
)

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
}

var globalUDPRelayStats udpRelayStats

// relayStatsActive is bench/env only; prod hot path checks this once per batch (single atomic load).
var relayStatsActive atomic.Bool

func init() {
	if os.Getenv("MASQUE_CONNECT_UDP_RELAY_STATS") == "1" {
		relayStatsActive.Store(true)
	}
}

func relayStatsEnabled() bool {
	return relayStatsActive.Load()
}

// EnableRelayStatsForBench turns on relay counters for segment localize gates.
func EnableRelayStatsForBench() {
	relayStatsActive.Store(true)
}

// beginRelaySessionStats resets counters when stats are active; returns an end hook for defer.
func beginRelaySessionStats(tag string) func() {
	if !relayStatsEnabled() {
		return func() {}
	}
	ResetUDPRelayStats()
	return func() { LogUDPRelayStats(tag) }
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
	}
}

// LogUDPRelayStats emits a machine-parseable bench line when stats env is enabled.
func LogUDPRelayStats(tag string) {
	if !relayStatsEnabled() {
		return
	}
	s := SnapshotUDPRelayStats()
	log.Printf(
		"RESULT_RELAY_STATS tag=%s c2s_in=%d c2s_udp_out=%d c2s_drop_malformed=%d c2s_drop_oversize=%d s2c_udp_in=%d s2c_dgram_out=%d s2c_drop_oversize=%d s2c_drop_send=%d",
		tag,
		s.C2SDatagramIn,
		s.C2SUDPPayloadOut,
		s.C2SDropMalformed,
		s.C2SDropOversize,
		s.S2CUDPIn,
		s.S2CDatagramOut,
		s.S2CDropOversize,
		s.S2CDropSendFail,
	)
}
