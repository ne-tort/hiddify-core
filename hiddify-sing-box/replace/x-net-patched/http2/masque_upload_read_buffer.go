package http2

import (
	"os"
	"strconv"
	"strings"
)

const envH2UploadReadBytes = "MASQUE_H2_UPLOAD_READ_BYTES"

// masqueUploadReadBufferLen returns the body.Read scratch size for MASQUE bulk upload.
// Default 256 KiB coalesces pipe reads before TLS bulk flush (frame-sized minLen caused Docker upload ~2× gap).
func masqueUploadReadBufferLen(minLen, maxFrameSize int) int {
	const defaultBuf = 256 << 10
	const maxBuf = 512 << 10
	n := defaultBuf
	if v := strings.TrimSpace(os.Getenv(envH2UploadReadBytes)); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			n = parsed
		}
	}
	if n < minLen {
		n = minLen
	}
	if maxFrameSize > 0 && n < maxFrameSize {
		n = maxFrameSize
	}
	if n > maxBuf {
		n = maxBuf
	}
	return n
}
