package conn

// H2BidiDownloadDrainEnabled reports whether H2 CONNECT-stream tunnels discard unread
// response DATA during upload-only phases. Prod: always on.
func H2BidiDownloadDrainEnabled() bool { return true }
