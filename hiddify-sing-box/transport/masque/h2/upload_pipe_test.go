package h2

import (
	"io"
	"testing"
)

func TestConnectUploadPipeBufferedWriteRead(t *testing.T) {
	r, w := NewConnectUploadPipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 64*1024)
		_, _ = io.ReadFull(r, buf)
	}()
	payload := make([]byte, 128*1024)
	if _, err := w.Write(payload); err != nil {
		t.Fatalf("buffered write before read: %v", err)
	}
	<-done
	_ = w.Close()
}
