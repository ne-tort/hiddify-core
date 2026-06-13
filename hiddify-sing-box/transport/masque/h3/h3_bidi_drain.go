package h3

import (
	"os"
	"strings"
)

const envH3BidiDownloadDrain = "MASQUE_H3_BIDI_DOWNLOAD_DRAIN"

// H3BidiDownloadDrainEnabled reports whether H3 CONNECT-stream tunnels discard unread
// response DATA during upload-only phases (iperf banner / ACK clock). One *http3.Stream
// stalls request-body writes when peer response DATA is not drained (parity stream/h2_bidi_drain).
// Disable with MASQUE_H3_BIDI_DOWNLOAD_DRAIN=0.
func H3BidiDownloadDrainEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(envH3BidiDownloadDrain))) {
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
}
