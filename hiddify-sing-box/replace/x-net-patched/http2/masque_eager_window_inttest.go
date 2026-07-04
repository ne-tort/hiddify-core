//go:build masque_inttest_heavy

package http2

// SetMasqueDownloadEagerWindowEnabled toggles eager client WINDOW_UPDATE (inttest only).
func SetMasqueDownloadEagerWindowEnabled(on bool) {
	masqueDownloadEagerWindowOn = on
}
