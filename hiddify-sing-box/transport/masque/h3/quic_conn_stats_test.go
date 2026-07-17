package h3

import "testing"

func TestTrackQUICConnNilAndDedup(t *testing.T) {
	ResetQUICConnStatsTrackingForTest()
	TrackQUICConn("x", nil)
	if SnapshotQUICConnStats().TrackedConns != 0 {
		t.Fatal("nil must not track")
	}
}
