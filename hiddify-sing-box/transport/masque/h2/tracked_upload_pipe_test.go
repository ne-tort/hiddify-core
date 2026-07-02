package h2

import (
	"io"
	"testing"
)

func TestTrackedUploadPipeWriterOpenUntilClose(t *testing.T) {
	t.Parallel()
	r, w := NewTrackedUploadPipe()
	body := &ExtendedConnectUploadBody{Pipe: r, Writer: w}
	if !body.MasqueUploadWriterOpen() {
		t.Fatal("writer should be open after create")
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 16)
		_, _ = body.Read(buf)
	}()
	if _, err := w.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	<-done
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if body.MasqueUploadWriterOpen() {
		t.Fatal("writer should be closed after Close")
	}
	buf := make([]byte, 8)
	n, err := body.Read(buf)
	if n != 0 || err != io.EOF {
		t.Fatalf("read after writer close: n=%d err=%v", n, err)
	}
}
