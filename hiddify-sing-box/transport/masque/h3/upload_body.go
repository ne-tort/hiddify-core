package h3

import (
	"io"
	"os"
	"strconv"
	"strings"
)

const (
	defaultUploadChunkBytes = 4 * 1024
	// defaultDuplexUploadChunkBytes balances interleave vs HTTP/3 framing overhead on one bidi stream.
	defaultDuplexUploadChunkBytes = 16 * 1024
	envH3UploadChunkKB      = "MASQUE_H3_CONNECT_UPLOAD_CHUNK"
	envH2UploadChunkKB      = "MASQUE_H2_CONNECT_UPLOAD_CHUNK"
	envH3DuplexUploadChunkKB = "MASQUE_H3_DUPLEX_UPLOAD_CHUNK"
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

// H3UploadChunkBytes returns CONNECT upload chunk size for the leg.
// Bootstrap duplex (downloadActive + one direction started) uses duplex chunk (default 16 KiB)
// so FC/wake interleave can start on one bidi stream. Steady concurrent duplex (both
// downloadDelivered and duplexUploadStarted) ramps to 64 KiB — parity server relay and
// single-leg prod path; micro-chunks there cap aggregate bidi throughput (~330 Mbit/s).
func H3UploadChunkBytes(downloadActive bool, downloadDelivered bool, duplexUploadStarted bool) int {
	if downloadActive && downloadDelivered && duplexUploadStarted {
		return tunnelWriteToBufLen
	}
	if downloadActive && (downloadDelivered || duplexUploadStarted) {
		return duplexUploadChunkBytesFromEnv()
	}
	return tunnelWriteToBufLen
}

func duplexUploadChunkBytesFromEnv() int {
	if kb := parseUploadChunkKB(os.Getenv(envH3DuplexUploadChunkKB)); kb > 0 {
		return kb * 1024
	}
	if kb := parseUploadChunkKB(os.Getenv(envH3UploadChunkKB)); kb > 0 {
		return kb * 1024
	}
	if kb := parseUploadChunkKB(os.Getenv(envH2UploadChunkKB)); kb > 0 {
		return kb * 1024
	}
	return defaultDuplexUploadChunkBytes
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
	return writeChunkedWake(w, p, chunk, nil)
}

func writeChunkedWake(w io.Writer, p []byte, chunk int, afterChunk func(wrote int)) (int, error) {
	if w == nil {
		return 0, io.ErrClosedPipe
	}
	if chunk <= 0 {
		n, err := w.Write(p)
		if n > 0 && afterChunk != nil {
			afterChunk(n)
		}
		return n, err
	}
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > chunk {
			n = chunk
		}
		wrote, err := w.Write(p[:n])
		total += wrote
		if wrote > 0 && afterChunk != nil {
			afterChunk(wrote)
		}
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
