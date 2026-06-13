package h2

import (
	"bytes"
	"testing"
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

func TestWriteAllIOWriterCompletesPartialWrites(t *testing.T) {
	w := &chunkWriter{max: 7}
	payload := bytes.Repeat([]byte{'z'}, 100)
	n, err := WriteAll(w, payload)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(payload) {
		t.Fatalf("WriteAll n=%d want %d", n, len(payload))
	}
	if !bytes.Equal(payload, w.buf.Bytes()) {
		t.Fatalf("payload mismatch")
	}
}
