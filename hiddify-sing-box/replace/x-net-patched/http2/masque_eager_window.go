package http2

import (
	"os"
	"strings"
)

const envH2DownloadEagerWindow = "MASQUE_H2_DOWNLOAD_EAGER_WINDOW"

// masqueDownloadEagerWindowEnabled mirrors transport/masque/h2.DownloadEagerWindowEnabled:
// client-side WINDOW_UPDATE per read chunk (parity quic-go masque_threshold threshold=0).
func masqueDownloadEagerWindowEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(envH2DownloadEagerWindow))) {
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
}
