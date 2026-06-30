package conn

import "testing"

func TestH3LegRoleFromStreamRole(t *testing.T) {
	if got := H3LegRoleFromStreamRole("download"); got != H3LegDownload {
		t.Fatalf("download: got %v want %v", got, H3LegDownload)
	}
	if got := H3LegRoleFromStreamRole("upload"); got != H3LegUpload {
		t.Fatalf("upload: got %v want %v", got, H3LegUpload)
	}
	if got := H3LegRoleFromStreamRole(""); got != H3LegBidi {
		t.Fatalf("empty: got %v want %v", got, H3LegBidi)
	}
	if H3LegUpload.c2sHTTPBatchFlush() != h3WriteHTTPBatchFlushUpload {
		t.Fatalf("upload batch flush: got %d want %d", H3LegUpload.c2sHTTPBatchFlush(), h3WriteHTTPBatchFlushUpload)
	}
	if H3LegBidi.c2sHTTPBatchFlush() != h3WriteHTTPBatchFlush {
		t.Fatalf("bidi batch flush: got %d want %d", H3LegBidi.c2sHTTPBatchFlush(), h3WriteHTTPBatchFlush)
	}
	if H3LegUpload.s2cPrefetchEnabled() {
		t.Fatal("upload leg must not run S2C prefetch")
	}
	if !H3LegDownload.s2cPrefetchEnabled() || !H3LegBidi.s2cPrefetchEnabled() {
		t.Fatal("download/bidi legs must run S2C prefetch")
	}
}

func TestH3ConnUploadLegSkipsPrefetchRing(t *testing.T) {
	cfg := H3ConnConfig{LegRole: H3LegUpload}
	if cfg.LegRole.s2cPrefetchEnabled() {
		t.Fatal("upload leg config must disable S2C prefetch")
	}
}
