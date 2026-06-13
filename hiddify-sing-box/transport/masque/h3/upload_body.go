package h3

import (
	"io"
	"os"
	"strconv"
	"strings"
)

const (
	defaultUploadChunkBytes = 4 * 1024
	envH3UploadChunkKB      = "MASQUE_H3_CONNECT_UPLOAD_CHUNK"
	envH2UploadChunkKB      = "MASQUE_H2_CONNECT_UPLOAD_CHUNK"
)

// UploadFlushPolicy controls how bulk CONNECT-stream upload is split before hitting the wire.
// Chunking keeps HTTP/3 DATA frames small so download ACKs advance during iperf -R duplex.
type UploadFlushPolicy struct {
	ChunkBytes int
}

// H3UploadFlushPolicy returns the active H3 CONNECT-stream upload flush policy.
func H3UploadFlushPolicy() UploadFlushPolicy {
	return UploadFlushPolicy{ChunkBytes: uploadChunkBytesFromEnv()}
}

func (p UploadFlushPolicy) passthrough() bool {
	return p.ChunkBytes <= 0
}

func uploadChunkBytesFromEnv() int {
	for _, key := range []string{envH3UploadChunkKB, envH2UploadChunkKB} {
		if kb := parseUploadChunkKB(os.Getenv(key)); kb > 0 {
			return kb * 1024
		}
	}
	return defaultUploadChunkBytes
}

func parseUploadChunkKB(raw string) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	kb, err := strconv.Atoi(raw)
	if err != nil || kb <= 0 {
		return -1
	}
	if kb > 1024 {
		kb = 1024
	}
	return kb
}

func writeChunked(w io.Writer, p []byte, chunk int) (int, error) {
	if w == nil {
		return 0, io.ErrClosedPipe
	}
	if chunk <= 0 {
		return w.Write(p)
	}
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > chunk {
			n = chunk
		}
		wrote, err := w.Write(p[:n])
		total += wrote
		if err != nil {
			return total, err
		}
		p = p[wrote:]
	}
	return total, nil
}

func copyChunked(w io.Writer, r io.Reader, chunk int) (int64, error) {
	if chunk <= 0 {
		return io.Copy(w, r)
	}
	buf := make([]byte, chunk)
	var total int64
	for {
		n, err := r.Read(buf)
		if n > 0 {
			wrote, werr := writeChunked(w, buf[:n], chunk)
			total += int64(wrote)
			if werr != nil {
				return total, werr
			}
			if wrote < n {
				return total, io.ErrShortWrite
			}
		}
		if err != nil {
			if err == io.EOF {
				return total, nil
			}
			return total, err
		}
	}
}
