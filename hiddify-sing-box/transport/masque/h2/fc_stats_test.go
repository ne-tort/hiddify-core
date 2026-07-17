package h2_test

import (
	"testing"

	h2c "github.com/sagernet/sing-box/transport/masque/h2"
)

func TestBulkHTTP2ServerConfigMaxConcurrentStreams(t *testing.T) {
	t.Parallel()
	srv := h2c.BulkHTTP2ServerConfig()
	if srv.MaxConcurrentStreams != h2c.DefaultMaxConcurrentStreams {
		t.Fatalf("MaxConcurrentStreams=%d want default %d", srv.MaxConcurrentStreams, h2c.DefaultMaxConcurrentStreams)
	}
	lab := h2c.BulkHTTP2ServerConfigResolved(h2c.Resolve(h2c.LabBulkTuning()))
	if lab.MaxConcurrentStreams != h2c.LabBulkMaxConcurrentStreams {
		t.Fatalf("lab MCS=%d want %d", lab.MaxConcurrentStreams, h2c.LabBulkMaxConcurrentStreams)
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
