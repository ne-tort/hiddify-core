package http2

// masqueUploadEagerWindowEnabled credits inbound request DATA to the peer as soon as
// bytes are buffered for the handler (CONNECT-UDP bulk upload). Prod: always on.
func masqueUploadEagerWindowEnabled() bool { return true }
