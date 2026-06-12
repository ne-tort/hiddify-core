package connectudp

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

// partialFailWriter returns a short write together with an error on the first call (allowed by io.Writer).
type partialFailWriter struct {
	calls int
}

func (w *partialFailWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.calls == 1 {
		if len(p) < 2 {
			return len(p), errors.New("test short write")
		}
		return 2, errors.New("test short write")
	}
	return len(p), nil
}

func (*partialFailWriter) Close() error { return nil }

func TestH2UploadWriterPropagatesPartialWriteOnError(t *testing.T) {
	c := NewH2PacketConn(H2PacketConnConfig{ReqBody: &partialFailWriter{}})
	uw := &h2UploadWriter{c: c}
	n, err := uw.Write([]byte("hello"))
	require.Error(t, err)
	require.Equal(t, 2, n, "io.Writer must return bytes written before error")
}
