package connectudp

import (
	"io"

	h2c "github.com/sagernet/sing-box/transport/masque/h2"
)

// H2RequestBodyWriter forwards CONNECT-UDP uplink capsules to the HTTP/2 request
// body without an intermediate bufio layer: each Write must reach net/http immediately so
// Extended CONNECT request DATA is not batched behind a 64 KiB buffer (bench dig / DNS UDP).
type H2RequestBodyWriter struct {
	inner io.WriteCloser
}

// NewH2RequestBodyWriter wraps the CONNECT-UDP Extended CONNECT request body pipe.
func NewH2RequestBodyWriter(inner io.WriteCloser) *H2RequestBodyWriter {
	return &H2RequestBodyWriter{inner: inner}
}

func (w *H2RequestBodyWriter) Write(p []byte) (int, error) {
	return h2c.WriteAll(w.inner, p)
}

func (w *H2RequestBodyWriter) Close() error {
	return w.inner.Close()
}
