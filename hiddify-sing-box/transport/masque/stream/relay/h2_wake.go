package relay

// Prod wake defaults for H2 CONNECT-stream relay (no env / no exported setters).
// Upload wake OFF (H2-S2). Download flush ON (load-bearing for Extended CONNECT).
var (
	h2UploadWakePerChunk   = false
	h2DownloadWakePerChunk = true
)
