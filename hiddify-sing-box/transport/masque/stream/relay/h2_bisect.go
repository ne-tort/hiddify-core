package relay

// h2UploadWakePerChunk gates per-chunk cross-leg flush on server upload relay (prod default on).
var h2UploadWakePerChunk = true

// h2DownloadWakePerChunk gates per-chunk flush on server download relay (prod default on).
var h2DownloadWakePerChunk = true

// SetH2UploadWakePerChunkEnabled toggles relayTunnelWakeH2AfterUploadRead (bisect / unit tests only).
func SetH2UploadWakePerChunkEnabled(on bool) {
	h2UploadWakePerChunk = on
}

// SetH2DownloadWakePerChunkEnabled toggles relayTunnelWakeH2AfterDownloadWrite (bisect / unit tests only).
func SetH2DownloadWakePerChunkEnabled(on bool) {
	h2DownloadWakePerChunk = on
}

// SetH2RelayPlainEnabled disables both upload and download per-chunk wakes (h2o plain io.Copy shape).
func SetH2RelayPlainEnabled(plain bool) {
	h2UploadWakePerChunk = !plain
	h2DownloadWakePerChunk = !plain
}
