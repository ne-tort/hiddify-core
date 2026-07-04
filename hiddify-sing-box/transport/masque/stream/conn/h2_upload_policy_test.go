package conn

import "testing"

func TestH2ConnectUploadChunkBytesProdDefault(t *testing.T) {
	if H2ConnectUploadChunkBytes != H2ConnectStreamWriteToBufLen {
		t.Fatalf("H2ConnectUploadChunkBytes: got %d want %d (H3/bulk-flush parity)", H2ConnectUploadChunkBytes, H2ConnectStreamWriteToBufLen)
	}
	if H2ConnectUploadChunkBytes != 256*1024 {
		t.Fatalf("H2ConnectUploadChunkBytes: got %d want 256 KiB", H2ConnectUploadChunkBytes)
	}
	if H2ConnectStreamWriteToBufLen != 256*1024 {
		t.Fatalf("H2ConnectStreamWriteToBufLen: got %d want %d", H2ConnectStreamWriteToBufLen, 256*1024)
	}
}
