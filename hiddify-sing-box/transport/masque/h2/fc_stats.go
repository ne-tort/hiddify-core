package h2

import "golang.org/x/net/http2"

// FCStats is a snapshot of H2 CONNECT Extended CONNECT FC / stall counters (always-on).
type FCStats = http2.MasqueH2Stats

// SnapshotFCStats returns point-in-time H2 FC/loss-related counters for benches and diagnostics.
func SnapshotFCStats() FCStats {
	return http2.SnapshotMasqueH2Stats()
}

// ResetFCStatsForTest clears H2 FC counters (unit tests only).
func ResetFCStatsForTest() {
	http2.ResetMasqueH2StatsForTest()
}
