package h3_test

import (
	"testing"

	"github.com/sagernet/sing-box/transport/masque/h3"
)

func TestSnapshotQUICConnStatsEmpty(t *testing.T) {
	t.Parallel()
	h3.ResetQUICConnStatsTrackingForTest()
	s := h3.SnapshotQUICConnStats()
	if s.TrackedConns != 0 || s.PacketsLost != 0 {
		t.Fatalf("unexpected snapshot %+v", s)
	}
}

func TestTrackQUICConnNilSafe(t *testing.T) {
	t.Parallel()
	h3.ResetQUICConnStatsTrackingForTest()
	h3.TrackQUICConn("client", nil)
	s := h3.SnapshotQUICConnStats()
	if s.TrackedConns != 0 {
		t.Fatalf("nil conn should not be tracked, got %+v", s)
	}
}
