package h3

import (
	"os"
	"strings"
)

const envDownloadEagerWindow = "MASQUE_QUIC_DOWNLOAD_EAGER_WINDOW"

// DownloadEagerWindowEnabled reports whether CONNECT-stream download should emit
// MAX_STREAM_DATA on every read chunk (B7 / quic-go flowcontrol threshold 0). Default on.
func DownloadEagerWindowEnabled() bool {
	return strings.TrimSpace(os.Getenv(envDownloadEagerWindow)) != "0"
}
