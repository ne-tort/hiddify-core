package conn

import "testing"

func TestH2UploadPolicyProdDefaults(t *testing.T) {
	p := CurrentH2UploadPolicy()
	if p.WrapChunkBytes() != 0 {
		t.Fatalf("wrap chunk: got %d want 0 (bulk passthrough)", p.WrapChunkBytes())
	}
	if p.ReadChunkBytes() != defaultH2ConnectUploadChunkBytes {
		t.Fatalf("read chunk: got %d want %d", p.ReadChunkBytes(), defaultH2ConnectUploadChunkBytes)
	}
	if !p.BulkFlushEnabled() {
		t.Fatal("bulk flush should be enabled")
	}
	if got := H2ConnectUploadChunkBytes(); got != defaultH2ConnectUploadChunkBytes {
		t.Fatalf("H2ConnectUploadChunkBytes: got %d want %d", got, defaultH2ConnectUploadChunkBytes)
	}
}
