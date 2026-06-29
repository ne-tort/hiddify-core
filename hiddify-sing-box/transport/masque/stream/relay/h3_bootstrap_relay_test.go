package relay

import (
	"bytes"
	"io"
	"testing"
)

func TestStripH3ClientBootstrapUploadDiscardsZeros(t *testing.T) {
	body := io.NopCloser(bytes.NewReader(make([]byte, 4096)))
	r := StripH3ClientBootstrapUpload(body)
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Fatalf("expected empty after strip, got %d bytes", len(out))
	}
}

func TestStripH3ClientBootstrapUploadPassthroughPayload(t *testing.T) {
	payload := append(make([]byte, 4096), 'x')
	body := io.NopCloser(bytes.NewReader(payload))
	r := StripH3ClientBootstrapUpload(body)
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0] != 'x' {
		t.Fatalf("got %q want x", out)
	}
}
