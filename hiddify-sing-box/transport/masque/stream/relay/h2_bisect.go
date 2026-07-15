package relay

// h2UploadWakePerChunk gates per-chunk cross-leg flush on server upload relay.
// Prod default OFF (H2-S2): field A/B showed upload +5.6% with wake off; download flush stays on.
var h2UploadWakePerChunk = false

// h2DownloadWakePerChunk gates per-chunk flush on server download relay (prod default on — load-bearing).
var h2DownloadWakePerChunk = true

// SetH2UploadWakePerChunkEnabled toggles relayTunnelWakeH2AfterUploadRead (unit/lab bisect only).
func SetH2UploadWakePerChunkEnabled(on bool) {
	h2UploadWakePerChunk = on
}

// SetH2DownloadWakePerChunkEnabled toggles relayTunnelWakeH2AfterDownloadWrite (unit/lab bisect only).
func SetH2DownloadWakePerChunkEnabled(on bool) {
	h2DownloadWakePerChunk = on
}

// SetH2RelayPlainEnabled disables both upload and download per-chunk wakes (INCOMPATIBLE on H2 — tests only).
func SetH2RelayPlainEnabled(plain bool) {
	h2UploadWakePerChunk = !plain
	h2DownloadWakePerChunk = !plain
}
