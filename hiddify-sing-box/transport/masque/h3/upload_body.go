package h3

import (
	"io"
)

// H3UploadFlushChunkBytes splits bulk CONNECT-stream upload before hitting the wire (64 KiB).
const H3UploadFlushChunkBytes = 64 * 1024

// H3UploadChunkBytes returns CONNECT upload chunk size (single prod profile: 256 KiB).
func H3UploadChunkBytes(downloadActive bool, downloadDelivered bool, duplexUploadStarted bool) int {
	_ = downloadActive
	_ = downloadDelivered
	_ = duplexUploadStarted
	return TunnelWriteToBufLen
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
		batchBytes = TunnelWriteToBufLen
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
