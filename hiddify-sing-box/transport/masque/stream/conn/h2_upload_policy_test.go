package conn

import "testing"

func TestH2ConnectUploadChunkBytesProdDefault(t *testing.T) {
	if H2ConnectUploadChunkBytes != 64*1024 {
		t.Fatalf("H2ConnectUploadChunkBytes: got %d want %d", H2ConnectUploadChunkBytes, 64*1024)
	}
}
