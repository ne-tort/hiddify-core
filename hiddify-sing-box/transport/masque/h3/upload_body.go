package h3

import (
	"io"
)

const (
	defaultUploadChunkBytes       = 64 * 1024
	defaultDuplexUploadChunkBytes = 64 * 1024
)

// UploadFlushPolicy controls how bulk CONNECT-stream upload is split before hitting the wire.
type UploadFlushPolicy struct {
	ChunkBytes int
}

// H3UploadFlushPolicy returns the active H3 CONNECT-stream upload flush policy.
func H3UploadFlushPolicy() UploadFlushPolicy {
	return UploadFlushPolicy{ChunkBytes: defaultUploadChunkBytes}
}

// H3UploadChunkBytes returns CONNECT upload chunk size for the leg.
func H3UploadChunkBytes(downloadActive bool, downloadDelivered bool, duplexUploadStarted bool) int {
	if downloadActive && downloadDelivered && duplexUploadStarted {
		return tunnelWriteToBufLen
	}
	if downloadActive && (downloadDelivered || duplexUploadStarted) {
		return defaultDuplexUploadChunkBytes
	}
	return tunnelWriteToBufLen
}

func (p UploadFlushPolicy) passthrough() bool {
	return p.ChunkBytes <= 0
}

func writeChunked(w io.Writer, p []byte, chunk int) (int, error) {
	return writeChunkedWake(w, p, chunk, nil)
}

// writeBatchedWake writes p in one syscall and invokes wake only after batchBytes accumulate.
func writeBatchedWake(w io.Writer, p []byte, batchBytes int, pending *int, wake func()) (int, error) {
	if w == nil {
		return 0, io.ErrClosedPipe
	}
	if batchBytes <= 0 {
		batchBytes = tunnelWriteToBufLen
	}
	n, err := w.Write(p)
	if n > 0 && wake != nil && pending != nil {
		*pending += n
		if *pending >= batchBytes {
			*pending = 0
			wake()
		}
	}
	return n, err
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
