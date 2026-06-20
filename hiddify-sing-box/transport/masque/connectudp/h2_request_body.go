package connectudp

import (
	"io"

	h2c "github.com/sagernet/sing-box/transport/masque/h2"
)

// H2RequestBodyWriter forwards CONNECT-UDP uplink capsules to the HTTP/2 request body pipe
// without bufio: each coalesced flush reaches net/http directly (DNS / small-packet path).
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
	if w == nil || w.inner == nil {
		return nil
	}
	return w.inner.Close()
}
