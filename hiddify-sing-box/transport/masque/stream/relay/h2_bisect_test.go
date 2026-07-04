package relay

import "testing"

func TestH2UploadWakePerChunkProdDefault(t *testing.T) {
	if !h2UploadWakePerChunk {
		t.Fatal("prod default: h2UploadWakePerChunk must be true")
	}
	if !h2DownloadWakePerChunk {
		t.Fatal("prod default: h2DownloadWakePerChunk must be true")
	}
	SetH2UploadWakePerChunkEnabled(false)
	t.Cleanup(func() {
		SetH2UploadWakePerChunkEnabled(true)
		SetH2DownloadWakePerChunkEnabled(true)
	})
	if h2UploadWakePerChunk {
		t.Fatal("SetH2UploadWakePerChunkEnabled(false) had no effect")
	}
	SetH2RelayPlainEnabled(true)
	if h2UploadWakePerChunk || h2DownloadWakePerChunk {
		t.Fatal("SetH2RelayPlainEnabled(true) must disable both wakes")
	}
	SetH2RelayPlainEnabled(false)
	if !h2UploadWakePerChunk || !h2DownloadWakePerChunk {
		t.Fatal("SetH2RelayPlainEnabled(false) must restore both wakes")
	}
}
