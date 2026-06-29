package h3

import (
	"testing"
)

func TestBidiDuplexCoordDisabled(t *testing.T) {
	if BidiDuplexCoordEnabled() {
		t.Fatal("BidiDuplexCoordEnabled must stay false (direct h3 upload during download)")
	}
}

func TestTunnelConnPipeUploadUsesDirectWrite(t *testing.T) {
	var wrote int
	c := NewTunnelConn(TunnelConnParams{
		Writer: &chunkRecordWriter{fn: func(p []byte) (int, error) {
			wrote += len(p)
			return len(p), nil
		}},
	})
	if _, err := c.Write([]byte("xy")); err != nil {
		t.Fatal(err)
	}
	if wrote != 2 {
		t.Fatalf("expected direct pipe write, got %d bytes", wrote)
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }
