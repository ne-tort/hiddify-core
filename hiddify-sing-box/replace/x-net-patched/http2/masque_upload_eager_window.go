package http2

// masqueUploadEagerWindowOn credits inbound request DATA to the peer as soon as
// bytes are buffered for the handler (CONNECT Extended CONNECT bulk upload). Prod: on.
var masqueUploadEagerWindowOn = true

func masqueUploadEagerWindowEnabled() bool {
	return masqueUploadEagerWindowOn
}

// SetMasqueUploadEagerWindowEnabled toggles server upload eager WINDOW_UPDATE (unit/inttest only).
func SetMasqueUploadEagerWindowEnabled(on bool) {
	masqueUploadEagerWindowOn = on
}
