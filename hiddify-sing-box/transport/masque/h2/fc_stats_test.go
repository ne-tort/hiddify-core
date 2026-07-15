package h2_test

import (
	"testing"

	h2c "github.com/sagernet/sing-box/transport/masque/h2"
)

func TestBulkHTTP2ServerConfigMaxConcurrentStreams(t *testing.T) {
	t.Parallel()
	srv := h2c.BulkHTTP2ServerConfig()
	if srv.MaxConcurrentStreams != 4096 {
		t.Fatalf("MaxConcurrentStreams=%d want 4096 (H3 peer budget parity)", srv.MaxConcurrentStreams)
	}
}

func TestSnapshotFCStats(t *testing.T) {
	t.Parallel()
	h2c.ResetFCStatsForTest()
	s := h2c.SnapshotFCStats()
	if s.DownloadBodyBytes != 0 || s.AwaitFlowControlWaits != 0 {
		t.Fatalf("unexpected stats %+v", s)
	}
}
