package http2

import (
	"os"
	"strings"
)

const envH2UploadEagerWindow = "MASQUE_H2_UPLOAD_EAGER_WINDOW"

// masqueUploadEagerWindowEnabled credits inbound request DATA to the peer as soon as
// bytes are buffered for the handler (CONNECT-UDP bulk upload). Default on.
func masqueUploadEagerWindowEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(envH2UploadEagerWindow))) {
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
}
