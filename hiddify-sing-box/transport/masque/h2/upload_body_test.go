package h2

import (
	"bytes"
	"testing"
)

func TestUploadFlushPolicyDefaultChunk(t *testing.T) {
	p := H2UploadFlushPolicy()
	if p.ChunkBytes != defaultUploadChunkBytes {
		t.Fatalf("default chunk: got %d want %d", p.ChunkBytes, defaultUploadChunkBytes)
	}
}

func TestUploadFlushPolicyFromEnv(t *testing.T) {
	tests := []struct {
		env  string
		want int
	}{
		{"", defaultUploadChunkBytes},
		{"4", 4 * 1024},
		{"8", 8 * 1024},
		{"0", defaultUploadChunkBytes},
		{"-1", defaultUploadChunkBytes},
		{"bogus", defaultUploadChunkBytes},
		{"2048", 1024 * 1024},
	}
	for _, tc := range tests {
		t.Run(tc.env, func(t *testing.T) {
			if tc.env == "" {
				t.Setenv(envUploadChunkKB, "")
			} else {
				t.Setenv(envUploadChunkKB, tc.env)
			}
			got := H2UploadFlushPolicy().ChunkBytes
			if got != tc.want {
				t.Fatalf("chunk bytes: got %d want %d", got, tc.want)
			}
		})
	}
}

func TestH2ConnectChunkedUploadWriterFlushRequestBody(t *testing.T) {
	t.Setenv(envUploadChunkKB, "4")
	inner := &chunkRecordFlusherWriter{
		chunkRecordWriter: chunkRecordWriter{fn: func(p []byte) (int, error) {
			return len(p), nil
		}},
	}
	policy := H2UploadFlushPolicy()
	w := policy.Wrap(inner)
	if _, err := w.Write(bytes.Repeat([]byte("x"), 10*1024)); err != nil {
		t.Fatal(err)
	}
	if inner.flushCalls < 2 {
		t.Fatalf("expected FlushRequestBody per chunk, got %d flushes", inner.flushCalls)
	}
}

func TestH2ConnectChunkedUploadWriterSplitsWrites(t *testing.T) {
	t.Setenv(envUploadChunkKB, "4")
	var got []int
	policy := H2UploadFlushPolicy()
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
