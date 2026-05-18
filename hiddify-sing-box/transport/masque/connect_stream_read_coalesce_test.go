package masque

import (
	"bytes"
	"io"
	"testing"
)

type blockingSecondRead struct {
	first  []byte
	second []byte
	reads  int
}

func (r *blockingSecondRead) Read(p []byte) (int, error) {
	r.reads++
	if r.reads == 1 {
		return copy(p, r.first), nil
	}
	return copy(p, r.second), io.EOF
}

func (r *blockingSecondRead) ConnectStreamReadBuffered() bool {
	return false
}

func TestCoalesceConnectStreamReadDoesNotBlockWithoutBuffered(t *testing.T) {
	inner := &blockingSecondRead{
		first:  bytes.Repeat([]byte{1}, 1024),
		second: bytes.Repeat([]byte{2}, 1024),
	}
	dst := make([]byte, 64*1024)
	n, err := coalesceConnectStreamRead(inner, dst)
	if err != nil {
		t.Fatalf("coalesce: %v", err)
	}
	if n != len(inner.first) {
		t.Fatalf("got %d bytes want %d (second read must not run)", n, len(inner.first))
	}
	if inner.reads != 1 {
		t.Fatalf("inner reads=%d want 1", inner.reads)
	}
}
