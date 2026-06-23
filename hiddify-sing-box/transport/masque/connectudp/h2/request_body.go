package h2

import (
	"io"

	h2c "github.com/sagernet/sing-box/transport/masque/h2"
)

// RequestBodyWriter forwards CONNECT-UDP uplink capsules to the HTTP/2 request body pipe
// without bufio: each flush reaches net/http directly (DNS / small-packet path).
type RequestBodyWriter struct {
	inner io.WriteCloser
}

// NewRequestBodyWriter wraps the CONNECT-UDP Extended CONNECT request body pipe.
func NewRequestBodyWriter(inner io.WriteCloser) *RequestBodyWriter {
	return &RequestBodyWriter{inner: inner}
}

func (w *RequestBodyWriter) Write(p []byte) (int, error) {
	return h2c.WriteAll(w.inner, p)
}

func (w *RequestBodyWriter) Close() error {
	if w == nil || w.inner == nil {
		return nil
	}
	return w.inner.Close()
}
