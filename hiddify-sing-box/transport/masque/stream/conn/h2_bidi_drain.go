package conn

import (
	"os"
	"strings"
)

const EnvH2BidiDownloadDrain = "MASQUE_H2_BIDI_DOWNLOAD_DRAIN"

// H2BidiDownloadDrainEnabled reports whether H2 CONNECT-stream tunnels discard unread
// response DATA during upload-only phases (iperf banner / ACK clock). HTTP/2 client stacks
// can stall request-body writes when the peer sends response DATA and nothing drains it.
// Disable with MASQUE_H2_BIDI_DOWNLOAD_DRAIN=0.
func H2BidiDownloadDrainEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(EnvH2BidiDownloadDrain))) {
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
}
