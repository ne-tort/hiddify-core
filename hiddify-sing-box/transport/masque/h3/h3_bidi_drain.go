package h3

// H3BidiDownloadDrainEnabled reports whether H3 CONNECT-stream tunnels discard unread
// response DATA during upload-only phases (iperf banner / ACK clock). Prod: always on.
func H3BidiDownloadDrainEnabled() bool { return true }
