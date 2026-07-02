package h2

import (
	"io"
	"testing"
)

func TestConnectUploadShallowPipeQueuesMultipleWrites(t *testing.T) {
	t.Parallel()
	r, w := NewConnectUploadShallowPipe()
	defer func() { _ = r.Close() }()
	defer func() { _ = w.Close() }()

	chunk := make([]byte, 1600)
	for i := 0; i < 8; i++ {
		if _, err := w.Write(chunk); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	reader := r.(*uploadPipeReader)
	if got := reader.MasqueUploadBuffered(); got < 8*1600 {
		t.Fatalf("buffered=%d want >= %d", got, 8*1600)
	}
	if got := reader.UploadPipeCap(); got != connectUploadShallowPipeBuf {
		t.Fatalf("cap=%d want %d", got, connectUploadShallowPipeBuf)
	}
}

func TestConnectUploadShallowPipeWriterOpenUntilClose(t *testing.T) {
	t.Parallel()
	r, w := NewConnectUploadShallowPipe()
	reader := r.(*uploadPipeReader)
	if reader.MasqueUploadWriterOpen() {
		// writer not closed yet — good
	} else {
		t.Fatal("writer should be open")
	}
	_ = w.Close()
	if reader.MasqueUploadWriterOpen() {
		t.Fatal("writer should be closed after Close")
	}
}

func TestConnectUploadShallowPipeReaderDrainsWithoutWriterBlocked(t *testing.T) {
	t.Parallel()
	r, w := NewConnectUploadShallowPipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 256<<10)
		total := 0
		for total < 32*1600 {
			n, err := r.Read(buf)
			if n > 0 {
				total += n
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Errorf("read: %v", err)
				return
			}
		}
	}()
	chunk := make([]byte, 1600)
	for i := 0; i < 32; i++ {
		if _, err := w.Write(chunk); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	_ = w.Close()
	<-done
}
