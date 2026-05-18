package masque

import "io"

// h2ConnectUDPRequestBodyWriter forwards CONNECT-UDP uplink capsules to the HTTP/2 request
// body without an intermediate bufio layer: each Write must reach net/http immediately so
// Extended CONNECT request DATA is not batched behind a 64 KiB buffer (bench dig / DNS UDP).
type h2ConnectUDPRequestBodyWriter struct {
	inner io.WriteCloser
}

func newH2ConnectUDPRequestBodyWriter(inner io.WriteCloser) *h2ConnectUDPRequestBodyWriter {
	return &h2ConnectUDPRequestBodyWriter{inner: inner}
}

func (w *h2ConnectUDPRequestBodyWriter) Write(p []byte) (int, error) {
	return writeAllIOWriter(w.inner, p)
}

func (w *h2ConnectUDPRequestBodyWriter) Close() error {
	return w.inner.Close()
}

func flushH2ConnectUDPRequestBody(w io.Writer) {
	if w == nil {
		return
	}
	if f, ok := w.(interface{ Flush() error }); ok {
		_ = f.Flush()
	}
}
