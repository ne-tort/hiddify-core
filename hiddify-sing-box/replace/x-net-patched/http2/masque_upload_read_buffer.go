package http2

const masqueUploadReadBufferDefault = 256 << 10

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
