package http2

import "testing"

func TestMasqueUploadReadBufferLenDefault(t *testing.T) {
	got := masqueUploadReadBufferLen(16384, 16384)
	if got != 256<<10 {
		t.Fatalf("expected default 256KiB, got %d", got)
	}
}

func TestMasqueUploadReadBufferLenEnv(t *testing.T) {
	t.Setenv(envH2UploadReadBytes, "131072")
	got := masqueUploadReadBufferLen(16384, 16384)
	if got != 131072 {
		t.Fatalf("expected 131072, got %d", got)
	}
}
