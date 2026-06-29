package http2

// masqueUploadReadBufferLen returns the body.Read scratch size for MASQUE bulk upload.
// Prod: 256 KiB coalesces pipe reads before TLS bulk flush.
func masqueUploadReadBufferLen(minLen, maxFrameSize int) int {
	const defaultBuf = 256 << 10
	const maxBuf = 512 << 10
	n := defaultBuf
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
