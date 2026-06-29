package h2

import (
	"bytes"
	"testing"
)

func TestUploadFlushPolicyProdDefaults(t *testing.T) {
	p := H2UploadFlushPolicy()
	if p.ChunkBytes != 0 {
		t.Fatalf("prod chunk: got %d want 0 (bulk passthrough)", p.ChunkBytes)
	}
}

func TestH2ConnectChunkedUploadWriterSplitsWrites(t *testing.T) {
	var got []int
	policy := UploadFlushPolicy{ChunkBytes: 4 * 1024}
	w := policy.Wrap(&chunkRecordWriter{fn: func(p []byte) (int, error) {
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

func TestH2ConnectChunkedUploadWriterPokeFlushes(t *testing.T) {
	inner := &chunkRecordFlusherWriter{
		chunkRecordWriter: chunkRecordWriter{fn: func(p []byte) (int, error) {
			return len(p), nil
		}},
	}
	policy := UploadFlushPolicy{ChunkBytes: 4 * 1024}
	w := policy.Wrap(inner)
	if _, err := w.Write(bytes.Repeat([]byte("x"), 10*1024)); err != nil {
		t.Fatal(err)
	}
	if inner.flushCalls != 0 {
		t.Fatalf("bulk upload must not flush per chunk, got %d", inner.flushCalls)
	}
	if p, ok := w.(interface{ PokeH2BidiDownload() }); ok {
		p.PokeH2BidiDownload()
	} else {
		t.Fatal("chunked upload writer must implement PokeH2BidiDownload")
	}
	if inner.flushCalls != 1 {
		t.Fatalf("PokeH2BidiDownload must flush upload path, got %d flushes", inner.flushCalls)
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

type chunkRecordFlusherWriter struct {
	chunkRecordWriter
	flushCalls int
}

func (w *chunkRecordFlusherWriter) Flush() error {
	w.flushCalls++
	return nil
}
