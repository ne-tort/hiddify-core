package masque

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"
)

func TestConnectStreamDownloadFeederDrainsAheadOfConsumer(t *testing.T) {
	const chunk = 64 * 1024
	const chunks = 8
	payload := bytes.Repeat([]byte{'x'}, chunk*chunks)
	inner := &chunkedReadCloser{chunk: chunk, chunks: chunks, left: len(payload)}
	f := &connectStreamDownloadFeeder{}
	f.start(context.Background(), inner)
	out := make([]byte, 0, len(payload))
	buf := make([]byte, 32*1024)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			out = append(out, buf[:n]...)
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Fatal(err)
		}
	}
	if len(out) != len(payload) {
		t.Fatalf("got %d bytes want %d", len(out), len(payload))
	}
}

func TestConnectStreamDownloadFeederTryReadDrainsRing(t *testing.T) {
	f := &connectStreamDownloadFeeder{ring: make([]byte, 4096)}
	f.data = sync.NewCond(&f.mu)
	payload := []byte("hello-ring")
	if !f.writeRing(payload) {
		t.Fatal("writeRing")
	}
	dst := make([]byte, 32)
	n, ok := f.tryRead(dst)
	if !ok || n != len(payload) {
		t.Fatalf("tryRead n=%d ok=%v want %d", n, ok, len(payload))
	}
	n, ok = f.tryRead(dst)
	if ok || n != 0 {
		t.Fatalf("second tryRead n=%d ok=%v want block", n, ok)
	}
}
