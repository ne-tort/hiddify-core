package h2

import (
	"testing"
)

func TestUploadFlushPolicyProdDefaults(t *testing.T) {
	p := H2UploadFlushPolicy()
	if p.ChunkBytes != 0 {
		t.Fatalf("prod chunk: got %d want 0 (bulk passthrough)", p.ChunkBytes)
	}
}

func TestUploadFlushPolicyPassthrough(t *testing.T) {
	p := UploadFlushPolicy{ChunkBytes: 0}
	inner := &chunkRecordWriter{fn: func(p []byte) (int, error) { return len(p), nil }}
	if w := p.Wrap(inner); w != inner {
		t.Fatal("zero chunk policy must return inner writer unchanged")
	}
}

type chunkRecordWriter struct {
	fn func([]byte) (int, error)
}

func (w *chunkRecordWriter) Write(p []byte) (int, error) { return w.fn(p) }

func (w *chunkRecordWriter) Close() error { return nil }


