package masque

import (
	"bytes"
	"testing"
)

func TestH2ConnectChunkedUploadWriterSplitsWrites(t *testing.T) {
	t.Setenv("MASQUE_H2_CONNECT_UPLOAD_CHUNK", "4")
	var got []int
	w := newH2ConnectChunkedUploadWriter(&chunkRecordWriter{fn: func(p []byte) (int, error) {
		got = append(got, len(p))
		return len(p), nil
	}})
	if _, err := w.Write(bytes.Repeat([]byte("x"), 10*1024)); err != nil {
		t.Fatal(err)
	}
	if len(got) < 2 {
		t.Fatalf("expected multiple chunks, got %v", got)
	}
	for _, n := range got {
		if n > 4*1024 {
			t.Fatalf("chunk %d exceeds 4 KiB", n)
		}
	}
}

type chunkRecordWriter struct {
	fn func([]byte) (int, error)
}

func (w *chunkRecordWriter) Write(p []byte) (int, error) { return w.fn(p) }

func (w *chunkRecordWriter) Close() error { return nil }
