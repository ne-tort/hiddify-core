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

// TestH2ProdUploadPathPokeNotNoop (H2-T1a-01) — bidi download poke must flush upload via uploadPathAdapter.
func TestH2ProdUploadPathPokeNotNoop(t *testing.T) {
	inner := &pokeRecordFlusher{}
	paths := NewTunnelPaths(io.NopCloser(bytes.NewReader(nil)), inner)
	if paths.Upload == nil {
		t.Fatal("NewTunnelPaths must wire upload half")
	}
	if _, err := paths.Upload.Write(bytes.Repeat([]byte("x"), 8*1024)); err != nil {
		t.Fatal(err)
	}
	if f, ok := paths.Upload.(interface{ Flush() error }); ok {
		if err := f.Flush(); err != nil {
			t.Fatal(err)
		}
	} else {
		t.Fatal("prod upload path must implement Flush for bidi poke")
	}
	if inner.flushCalls != 1 {
		t.Fatalf("upload poke must flush inner writer, got %d flushes", inner.flushCalls)
	}
}






