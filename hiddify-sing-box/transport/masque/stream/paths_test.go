package stream

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
)

type nopCloserBuffer struct {
	bytes.Buffer
}

func (nopCloserBuffer) Close() error { return nil }

func TestTunnelPathsBidiRoundtrip(t *testing.T) {
	dlBody := bytes.NewReader([]byte("down"))
	ulBuf := &nopCloserBuffer{}
	paths := TunnelPaths{
		Download: &downloadPathAdapter{inner: io.NopCloser(dlBody)},
		Upload:   NewUploadPath(ulBuf),
	}
	conn := ConnFromTunnelPaths(context.Background(), paths, &net.TCPAddr{}, &net.TCPAddr{Port: 443})
	buf := make([]byte, 8)
	n, err := conn.Read(buf)
	if err != nil || n != 4 || string(buf[:n]) != "down" {
		t.Fatalf("read: n=%d err=%v buf=%q", n, err, buf[:n])
	}
	if _, err := conn.Write([]byte("up")); err != nil {
		t.Fatal(err)
	}
	if ulBuf.String() != "up" {
		t.Fatalf("upload: got %q", ulBuf.String())
	}
}

func TestNewTunnelPathsSplitsHalves(t *testing.T) {
	pr, pw := io.Pipe()
	t.Cleanup(func() {
		_ = pr.Close()
		_ = pw.Close()
	})
	paths := NewTunnelPaths(io.NopCloser(bytes.NewReader(nil)), pw)
	if paths.Download == nil || paths.Upload == nil {
		t.Fatal("expected non-nil download and upload paths")
	}
	if _, ok := paths.Download.(*downloadPathAdapter); !ok {
		t.Fatalf("download type: %T", paths.Download)
	}
	if _, ok := paths.Upload.(*uploadPathAdapter); !ok {
		t.Fatalf("upload type: %T", paths.Upload)
	}
}
