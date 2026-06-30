package conn

import "testing"

func TestH2ConnectUploadChunkBytesProdDefault(t *testing.T) {
	if got := H2ConnectUploadChunkBytes(); got != defaultH2ConnectUploadChunkBytes {
		t.Fatalf("H2ConnectUploadChunkBytes: got %d want %d", got, defaultH2ConnectUploadChunkBytes)
	}
}
