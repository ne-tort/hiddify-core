package h3

import (
	"bytes"
	"testing"
)

func TestH3UploadFlushChunkBytesProdDefault(t *testing.T) {
	if H3UploadFlushChunkBytes != 64*1024 {
		t.Fatalf("default chunk: got %d want %d", H3UploadFlushChunkBytes, 64*1024)
	}
}

func TestH3WriteChunkedSplitsWrites(t *testing.T) {
	var got []int
	w := &chunkRecordWriter{fn: func(p []byte) (int, error) {
		got = append(got, len(p))
		return len(p), nil
	}}
	if _, err := writeChunked(w, bytes.Repeat([]byte("x"), 10*1024), 4*1024); err != nil {
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
