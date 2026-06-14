package h2

import (
	"os"
	"strings"
)

const envH2DownloadEagerWindow = "MASQUE_H2_DOWNLOAD_EAGER_WINDOW"

// DownloadEagerWindowEnabled reports whether H2 CONNECT-stream client should grant download
// credit without RTT delay (parity MASQUE_QUIC_DOWNLOAD_EAGER_WINDOW on H3 / quic-go patches).
// Default on; disable with MASQUE_H2_DOWNLOAD_EAGER_WINDOW=0.
func DownloadEagerWindowEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(envH2DownloadEagerWindow))) {
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
}
