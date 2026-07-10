package h3

import "testing"

func TestH3UploadFlushChunkBytesProdDefault(t *testing.T) {
	if H3UploadFlushChunkBytes != 64*1024 {
		t.Fatalf("default chunk: got %d want %d", H3UploadFlushChunkBytes, 64*1024)
	}
}

func TestH3UploadChunkBytesUsesConnectStreamBufLen(t *testing.T) {
	want := connectStreamBufLen
	if got := H3UploadChunkBytes(true, true, true); got != want {
		t.Fatalf("duplex chunk: got %d want %d", got, want)
	}
	if got := H3UploadChunkBytes(false, false, false); got != want {
		t.Fatalf("sequential upload chunk: got %d want %d", got, want)
	}
}
