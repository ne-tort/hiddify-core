package conn

import "testing"

func TestH2UploadPolicyProdDefaults(t *testing.T) {
	p := CurrentH2UploadPolicy()
	if p.ReadChunkBytes() != defaultH2ConnectUploadChunkBytes {
		t.Fatalf("read chunk: got %d want %d", p.ReadChunkBytes(), defaultH2ConnectUploadChunkBytes)
	}
	if got := H2ConnectUploadChunkBytes(); got != defaultH2ConnectUploadChunkBytes {
		t.Fatalf("H2ConnectUploadChunkBytes: got %d want %d", got, defaultH2ConnectUploadChunkBytes)
	}
}
