package http2

var masqueDownloadEagerWindowOn = true

func masqueDownloadEagerWindowEnabled() bool {
	return masqueDownloadEagerWindowOn
}

// SetMasqueDownloadEagerWindowEnabled toggles eager WINDOW_UPDATE (unit/inttest only).
func SetMasqueDownloadEagerWindowEnabled(on bool) {
	masqueDownloadEagerWindowOn = on
}
