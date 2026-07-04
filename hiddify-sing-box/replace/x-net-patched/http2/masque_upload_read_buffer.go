package http2

var masqueUploadReadBufferDefault = 256 << 10

// masqueUploadReadBufferLen returns the body.Read scratch size for MASQUE bulk upload.
// Prod: 256 KiB coalesces pipe reads before TLS bulk flush.
func masqueUploadReadBufferLen(minLen, maxFrameSize int) int {
	const maxBuf = 512 << 10
	n := masqueUploadReadBufferDefault
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

// SetMasqueUploadReadBufferDefaultBytes overrides upload scratch buffer (bisect / unit tests only).
func SetMasqueUploadReadBufferDefaultBytes(n int) {
	if n > 0 {
		masqueUploadReadBufferDefault = n
	}
}
