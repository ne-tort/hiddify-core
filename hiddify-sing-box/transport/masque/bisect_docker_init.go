package masque

import (
	"os"
	"strconv"

	"github.com/sagernet/sing-box/transport/masque/stream/relay"
	"golang.org/x/net/http2"
)

// Docker perf-lab bisect hooks (STR-P2-H2-UPLOAD-ASYM). Inert unless MASQUE_BISECT_ALLOW=1.
// Prod dataplane never sets these env vars (see docs/masque/problems/STR-P2-H2-UPLOAD-ASYM-HYPOTHESES.md).
func init() {
	if os.Getenv("MASQUE_BISECT_ALLOW") != "1" {
		return
	}
	switch os.Getenv("MASQUE_BISECT_H2_EAGER_WINDOW") {
	case "0", "false", "off":
		http2.SetMasqueDownloadEagerWindowEnabled(false)
	case "1", "true", "on":
		http2.SetMasqueDownloadEagerWindowEnabled(true)
	}
	switch os.Getenv("MASQUE_BISECT_H2_RELAY_UPLOAD_WAKE") {
	case "0", "false", "off":
		relay.SetH2UploadWakePerChunkEnabled(false)
	case "1", "true", "on":
		relay.SetH2UploadWakePerChunkEnabled(true)
	}
	if v := os.Getenv("MASQUE_BISECT_H2_BULK_FLUSH_KIB"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			bytes := n << 10
			http2.SetMasqueBulkFlushThresholdBytes(bytes)
			http2.SetMasqueUploadPipeFlushWaterMarkBytes(bytes)
			http2.SetMasqueUploadReadBufferDefaultBytes(bytes)
		}
	}
}
