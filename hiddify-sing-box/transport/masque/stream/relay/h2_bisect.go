package relay

// h2UploadWakePerChunk gates per-chunk cross-leg flush on server upload relay (prod default on).
var h2UploadWakePerChunk = true

// SetH2UploadWakePerChunkEnabled toggles relayTunnelWakeH2AfterUploadRead (bisect / unit tests only).
func SetH2UploadWakePerChunkEnabled(on bool) {
	h2UploadWakePerChunk = on
}
