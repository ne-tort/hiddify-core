package masque

import (
	"io"
	"os"
	"strconv"
	"strings"
)

const defaultH2ConnectUploadChunk = 4 * 1024

func h2ConnectUploadChunkSize() int {
	raw := strings.TrimSpace(os.Getenv("MASQUE_H2_CONNECT_UPLOAD_CHUNK"))
	if raw == "" {
		return defaultH2ConnectUploadChunk
	}
	kb, err := strconv.Atoi(raw)
	if err != nil || kb <= 0 {
		return defaultH2ConnectUploadChunk
	}
	if kb > 1024 {
		kb = 1024
	}
	return kb * 1024
}

// h2ConnectChunkedUploadWriter splits bulk upload into small HTTP/2 DATA frames (ACK clock on iperf -R).
type h2ConnectChunkedUploadWriter struct {
	inner io.WriteCloser
	chunk int
}

func newH2ConnectChunkedUploadWriter(w io.WriteCloser) *h2ConnectChunkedUploadWriter {
	if w == nil {
		return nil
	}
	return &h2ConnectChunkedUploadWriter{inner: w, chunk: h2ConnectUploadChunkSize()}
}

func (w *h2ConnectChunkedUploadWriter) Write(p []byte) (int, error) {
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

func (w *h2ConnectChunkedUploadWriter) Close() error {
	if w == nil || w.inner == nil {
		return nil
	}
	return w.inner.Close()
}

// h2ExtendedConnectUploadBody wraps the client's upload io.PipeReader so net/http's HTTP/2
// transport does not close it from cleanupWriteRequest when the peer half-closes the response
// (END_STREAM). Without this, upload on the CONNECT stream can be torn down while the tunnel
// is still active. Same idea as connect-ip-go DialHTTP2 (h2ExtendedConnectDuplexBody).
type h2ExtendedConnectUploadBody struct {
	pipe *io.PipeReader
}

func (b *h2ExtendedConnectUploadBody) Read(p []byte) (int, error) {
	if b == nil || b.pipe == nil {
		return 0, io.ErrUnexpectedEOF
	}
	return b.pipe.Read(p)
}

func (*h2ExtendedConnectUploadBody) Close() error {
	return nil
}
