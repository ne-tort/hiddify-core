package connectip

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

// chunkWriter simulates an io.Writer that may return n < len(p) without error (allowed by contract).
type chunkWriter struct {
	max int
	buf bytes.Buffer
}

func (c *chunkWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	n := len(p)
	if n > c.max {
		n = c.max
	}
	return c.buf.Write(p[:n])
}

func TestWriteAllWriterCompletesPartialWrites(t *testing.T) {
	w := &chunkWriter{max: 7}
	payload := bytes.Repeat([]byte{'z'}, 100)
	n, err := writeAllWriter(w, payload)
	require.NoError(t, err)
	require.Equal(t, len(payload), n)
	require.Equal(t, payload, w.buf.Bytes())
}
