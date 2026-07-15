package relay

import "testing"

func TestH2RelayWakeProdDefaults(t *testing.T) {
	t.Parallel()
	if h2UploadWakePerChunk {
		t.Fatal("prod default: h2UploadWakePerChunk must be false (H2-S2)")
	}
	if !h2DownloadWakePerChunk {
		t.Fatal("prod default: h2DownloadWakePerChunk must be true")
	}
}

func TestH2RelayWakeVarsToggleInPackage(t *testing.T) {
	origU, origD := h2UploadWakePerChunk, h2DownloadWakePerChunk
	t.Cleanup(func() {
		h2UploadWakePerChunk, h2DownloadWakePerChunk = origU, origD
	})
	h2UploadWakePerChunk = true
	if !h2UploadWakePerChunk {
		t.Fatal("package var assign failed")
	}
	h2UploadWakePerChunk = false
	h2DownloadWakePerChunk = false
	if h2UploadWakePerChunk || h2DownloadWakePerChunk {
		t.Fatal("expected both wakes off after assign")
	}
	h2DownloadWakePerChunk = true
}
