package h2

import (
	"bytes"
	"io"
	"testing"
)

type pokeRecordFlusher struct {
	flushCalls int
}

func (p *pokeRecordFlusher) Write(b []byte) (int, error) { return len(b), nil }

func (p *pokeRecordFlusher) Close() error { return nil }

func (p *pokeRecordFlusher) Flush() error {
	p.flushCalls++
	return nil
}

// TestH2ProdUploadPathPokeNotNoop (H2-T1a-01) — PokeH2BidiDownload must reach FlushRequestBody.
func TestH2ProdUploadPathPokeNotNoop(t *testing.T) {
	inner := &pokeRecordFlusher{}
	wrapped := UploadFlushPolicy{ChunkBytes: 4 * 1024}.Wrap(inner)
	if _, err := wrapped.Write(bytes.Repeat([]byte("x"), 8*1024)); err != nil {
		t.Fatal(err)
	}
	if inner.flushCalls != 0 {
		t.Fatal("prod bulk upload must not flush per chunk")
	}
	if p, ok := wrapped.(interface{ PokeH2BidiDownload() }); ok {
		p.PokeH2BidiDownload()
	} else {
		t.Fatal("chunked upload writer must implement PokeH2BidiDownload")
	}
	if inner.flushCalls != 1 {
		t.Fatalf("PokeH2BidiDownload must flush upload path, got %d flushes", inner.flushCalls)
	}
	pr, pw := io.Pipe()
	t.Cleanup(func() {
		_ = pr.Close()
		_ = pw.Close()
	})
	paths := NewTunnelPaths(io.NopCloser(bytes.NewReader(nil)), pw)
	if paths.Upload == nil {
		t.Fatal("NewTunnelPaths must wire upload half")
	}
}
