package relay

import "testing"

func TestH2UploadWakePerChunkProdDefaultOff(t *testing.T) {
	if h2UploadWakePerChunk {
		t.Fatal("prod default: h2UploadWakePerChunk must be false (H2-S2)")
	}
	if !h2DownloadWakePerChunk {
		t.Fatal("prod default: h2DownloadWakePerChunk must be true")
	}
	SetH2UploadWakePerChunkEnabled(true)
	t.Cleanup(func() {
		SetH2UploadWakePerChunkEnabled(false)
		SetH2DownloadWakePerChunkEnabled(true)
	})
	if !h2UploadWakePerChunk {
		t.Fatal("SetH2UploadWakePerChunkEnabled(true) had no effect")
	}
	SetH2RelayPlainEnabled(true)
	if h2UploadWakePerChunk || h2DownloadWakePerChunk {
		t.Fatal("SetH2RelayPlainEnabled(true) must disable both wakes")
	}
	SetH2RelayPlainEnabled(false)
	if !h2UploadWakePerChunk || !h2DownloadWakePerChunk {
		t.Fatal("SetH2RelayPlainEnabled(false) must restore both wakes on")
	}
}
