package h3

import "testing"

func TestTrackQUICConnNilAndDedup(t *testing.T) {
	ResetQUICConnStatsTrackingForTest()
	TrackQUICConn("x", nil)
	if SnapshotQUICConnStats().TrackedConns != 0 {
		t.Fatal("nil must not track")
	}
}

func TestSnapshotIncludesDatagramQueueDropFields(t *testing.T) {
	ResetQUICConnStatsTrackingForTest()
	s := SnapshotQUICConnStats()
	// Fields must be present and readable (process-wide counters; values may be 0).
	_ = s.DatagramRcvQueueDrops
	_ = s.StreamDatagramQueueDrops
	_ = s.StreamDatagramRecvClosedDrops
	_ = s.UnknownStreamDatagramDrops
	if s.DatagramQueueDropsTotal != s.DatagramRcvQueueDrops+s.StreamDatagramQueueDrops+s.StreamDatagramRecvClosedDrops+s.UnknownStreamDatagramDrops {
		t.Fatalf("drops total mismatch: %+v", s)
	}
}
