package flowcontrol

import (
	"os"
	"strconv"
	"strings"

	"github.com/quic-go/quic-go/internal/protocol"
)

const envDownloadEagerWindow = "MASQUE_QUIC_DOWNLOAD_EAGER_WINDOW"

// masqueDownloadEagerWindow reports whether CONNECT-stream download drains should emit
// MAX_STREAM_DATA on every read chunk (B7 instant_credit wire model). Default on.
func masqueDownloadEagerWindow() bool {
	return strings.TrimSpace(os.Getenv(envDownloadEagerWindow)) != "0"
}

// windowUpdateThreshold returns the fraction of receive window consumed before MAX_*_DATA.
// MASQUE fat streams default to 0.01 (faster credit return); stock quic-go uses 0.05.
// When MASQUE_QUIC_DOWNLOAD_EAGER_WINDOW=1 (default), threshold is 0 — credit returns per read.
func windowUpdateThreshold() float64 {
	if masqueDownloadEagerWindow() {
		return 0
	}
	raw := strings.TrimSpace(os.Getenv("MASQUE_QUIC_WINDOW_UPDATE_THRESHOLD"))
	if raw != "" {
		f, err := strconv.ParseFloat(raw, 64)
		if err == nil && f > 0 && f < 1 {
			return f
		}
	}
	if strings.TrimSpace(os.Getenv("MASQUE_QUIC_FAST_WINDOW_UPDATES")) != "0" {
		return 0.01
	}
	return protocol.WindowUpdateThreshold
}
