package h3

import (
	"bytes"
	"io"
	"testing"
)

func TestBidiDuplexCoordDisabled(t *testing.T) {
	for _, env := range []string{"", "1", "0", "off"} {
		t.Run(env, func(t *testing.T) {
			t.Setenv(envH3BidiDuplexCoord, env)
			if BidiDuplexCoordEnabled() {
				t.Fatal("BidiDuplexCoordEnabled must stay false (direct h3 upload during download)")
			}
		})
	}
}

func TestInterleaveDuplexTransferOrder(t *testing.T) {
	download := bytes.Repeat([]byte("d"), 32*1024)
	var (
		readIdx  int
		flushCnt int
	)
	_, err := interleaveDuplexTransfer(
		writerFunc(func(p []byte) (int, error) {
			return len(p), nil
		}),
		func(p []byte) (int, error) {
			if readIdx >= len(download) {
				return 0, io.EOF
			}
			n := copy(p, download[readIdx:])
			readIdx += n
			return n, nil
		},
		func() error {
			flushCnt++
			return nil
		},
		make([]byte, 16*1024),
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if flushCnt < 2 {
		t.Fatalf("expected upload flush before each download chunk, got %d flushes", flushCnt)
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
