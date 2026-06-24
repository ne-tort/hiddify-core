package http2

import (
	"os"
	"strconv"
	"strings"
)

const envH2UploadReadBytes = "MASQUE_H2_UPLOAD_READ_BYTES"

// masqueUploadReadBufferLen returns the body.Read scratch size for MASQUE bulk upload when
// MASQUE_H2_UPLOAD_READ_BYTES is set; otherwise keep the stock frame-sized buffer.
func masqueUploadReadBufferLen(minLen, maxFrameSize int) int {
	if v := strings.TrimSpace(os.Getenv(envH2UploadReadBytes)); v == "" {
		return minLen
	}
	const maxBuf = 512 << 10
	n := 256 << 10
	if parsed, err := strconv.Atoi(strings.TrimSpace(os.Getenv(envH2UploadReadBytes))); err == nil && parsed > 0 {
		n = parsed
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
