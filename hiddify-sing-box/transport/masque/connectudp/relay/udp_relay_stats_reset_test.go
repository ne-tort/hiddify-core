package relay

import "testing"

func TestResetUDPRelayStatsZerosAtomics(t *testing.T) {
	EnableRelayStatsForBench()
	globalUDPRelayStats.c2sDatagramIn.Store(7)
	globalUDPRelayStats.c2sUDPPayloadOut.Store(3)
	globalUDPRelayStats.c2sDropUDPWrite.Store(1)
	globalUDPRelayStats.s2cUDPIn.Store(9)
	ResetUDPRelayStats()
	s := SnapshotUDPRelayStats()
	if s.C2SDatagramIn != 0 || s.C2SUDPPayloadOut != 0 || s.C2SDropUDPWrite != 0 || s.S2CUDPIn != 0 {
		t.Fatalf("Reset did not zero: %+v", s)
	}
}
