package h2

import (
	"io"
	"os"
	"strconv"
	"strings"
)

const (
	defaultUploadChunkBytes = 4 * 1024
	envUploadChunkKB        = "MASQUE_H2_CONNECT_UPLOAD_CHUNK"
)

// UploadFlushPolicy controls how bulk CONNECT-stream upload is split before hitting the wire.
// Chunking keeps HTTP/2 DATA frames small so download ACKs advance during iperf -R duplex.
type UploadFlushPolicy struct {
	ChunkBytes int
}

// H2UploadFlushPolicy returns the active H2 CONNECT-stream upload flush policy.
func H2UploadFlushPolicy() UploadFlushPolicy {
	return UploadFlushPolicy{ChunkBytes: uploadChunkBytesFromEnv()}
}

func (p UploadFlushPolicy) passthrough() bool {
	return p.ChunkBytes <= 0
}

// Wrap applies chunking to w when ChunkBytes > 0.
func (p UploadFlushPolicy) Wrap(w io.WriteCloser) io.WriteCloser {
	if w == nil || p.passthrough() {
		return w
	}
	return &chunkedUploadWriter{inner: w, chunk: p.ChunkBytes}
}

func uploadChunkBytesFromEnv() int {
	raw := strings.TrimSpace(os.Getenv(envUploadChunkKB))
	if raw == "" {
		return defaultUploadChunkBytes
	}
	kb, err := strconv.Atoi(raw)
	if err != nil || kb <= 0 {
		return defaultUploadChunkBytes
	}
	if kb > 1024 {
		kb = 1024
	}
	return kb * 1024
}

// chunkedUploadWriter splits bulk upload into bounded writes (HTTP/2 DATA frame clock).
type chunkedUploadWriter struct {
	inner io.WriteCloser
	chunk int
}

func (w *chunkedUploadWriter) Write(p []byte) (int, error) {
	if w == nil || w.inner == nil {
		return 0, io.ErrClosedPipe
	}
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > w.chunk {
			n = w.chunk
		}
		wrote, err := w.inner.Write(p[:n])
		total += wrote
		if err != nil {
			return total, err
		}
		p = p[wrote:]
	}
	return total, nil
}

func (w *chunkedUploadWriter) Close() error {
	if w == nil || w.inner == nil {
		return nil
	}
	return w.inner.Close()
}
