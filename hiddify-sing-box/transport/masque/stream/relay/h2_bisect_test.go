package relay

import "testing"

func TestH2UploadWakePerChunkProdDefault(t *testing.T) {
	if !h2UploadWakePerChunk {
		t.Fatal("prod default: h2UploadWakePerChunk must be true")
	}
	SetH2UploadWakePerChunkEnabled(false)
	t.Cleanup(func() { SetH2UploadWakePerChunkEnabled(true) })
	if h2UploadWakePerChunk {
		t.Fatal("SetH2UploadWakePerChunkEnabled(false) had no effect")
	}
}
