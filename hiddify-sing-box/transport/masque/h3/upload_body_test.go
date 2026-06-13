package h3

import (
	"bytes"
	"testing"
)

func TestH3UploadFlushPolicyDefaultChunk(t *testing.T) {
	p := H3UploadFlushPolicy()
	if p.ChunkBytes != defaultUploadChunkBytes {
		t.Fatalf("default chunk: got %d want %d", p.ChunkBytes, defaultUploadChunkBytes)
	}
}

func TestH3UploadFlushPolicyFromEnv(t *testing.T) {
	tests := []struct {
		h3   string
		h2   string
		want int
	}{
		{"", "", defaultUploadChunkBytes},
		{"8", "", 8 * 1024},
		{"", "4", 4 * 1024},
		{"0", "4", 4 * 1024},
		{"bogus", "", defaultUploadChunkBytes},
		{"2048", "", 1024 * 1024},
	}
	for _, tc := range tests {
		t.Run(tc.h3+"/"+tc.h2, func(t *testing.T) {
			t.Setenv(envH3UploadChunkKB, tc.h3)
			t.Setenv(envH2UploadChunkKB, tc.h2)
			got := H3UploadFlushPolicy().ChunkBytes
			if got != tc.want {
				t.Fatalf("chunk bytes: got %d want %d", got, tc.want)
			}
		})
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
