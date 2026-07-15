package http2

import "testing"

func TestMasqueUploadReadBufferLenBaked(t *testing.T) {
	t.Parallel()
	got := masqueUploadReadBufferLen(16384, 16384)
	if got != 256<<10 {
		t.Fatalf("expected baked 256KiB, got %d", got)
	}
	got = masqueUploadReadBufferLen(400<<10, 16384)
	if got != 400<<10 {
		t.Fatalf("expected grow to minLen, got %d", got)
	}
	got = masqueUploadReadBufferLen(16384, 300<<10)
	if got != 300<<10 {
		t.Fatalf("expected grow to maxFrameSize, got %d", got)
	}
	got = masqueUploadReadBufferLen(600<<10, 600<<10)
	if got != 512<<10 {
		t.Fatalf("expected cap at 512KiB, got %d", got)
	}
}
