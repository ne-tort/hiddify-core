package h2

import (
	"io"

	"github.com/sagernet/sing-box/transport/masque/stream/conn"
)

// UploadFlushPolicy controls how bulk CONNECT-stream upload is split before hitting the wire.
// Chunking keeps HTTP/2 DATA frames small so download ACKs advance during iperf -R duplex.
type UploadFlushPolicy struct {
	ChunkBytes int
	bulkFlush  bool
}

// H2UploadFlushPolicy returns the active H2 CONNECT-stream upload flush policy.
func H2UploadFlushPolicy() UploadFlushPolicy {
	p := conn.CurrentH2UploadPolicy()
	return UploadFlushPolicy{
		ChunkBytes: p.WrapChunkBytes(),
		bulkFlush:  p.BulkFlushEnabled(),
	}
}

func (p UploadFlushPolicy) passthrough() bool {
	return p.ChunkBytes <= 0
}

// Wrap applies chunking to w when ChunkBytes > 0.
func (p UploadFlushPolicy) Wrap(w io.WriteCloser) io.WriteCloser {
	if w == nil || p.passthrough() {
		return w
	}
	return &chunkedUploadWriter{inner: w, chunk: p.ChunkBytes, bulkFlush: p.bulkFlush}
}

// chunkedUploadWriter splits bulk upload into bounded writes (HTTP/2 DATA frame clock).
type chunkedUploadWriter struct {
	inner     io.WriteCloser
	chunk     int
	bulkFlush bool
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
		if !w.bulkFlush {
			FlushRequestBody(w.inner)
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

// PokeH2BidiDownload flushes the HTTP/2 request-body path during concurrent download WriteTo.
func (w *chunkedUploadWriter) PokeH2BidiDownload() {
	if w == nil || w.inner == nil {
		return
	}
	FlushRequestBody(w.inner)
}
