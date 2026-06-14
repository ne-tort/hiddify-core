package stream

import (
	"bytes"
	"io"
	"testing"
)

func TestStripH2ClientBootstrapUploadDiscardsZeros(t *testing.T) {
	t.Setenv(envH2BidiBootstrapUpload, "4")
	body := io.NopCloser(io.MultiReader(
		bytes.NewReader(make([]byte, 4*1024)),
		bytes.NewReader([]byte("FAKEIPERF")),
	))
	r := StripH2ClientBootstrapUpload(body)
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(out, []byte("FAKEIPERF")) {
		t.Fatalf("got %q want FAKEIPERF", out)
	}
}

func TestStripH2ClientBootstrapUploadChunkedZeros(t *testing.T) {
	t.Setenv(envH2BidiBootstrapUpload, "4")
	const chunk = 512
	const total = 4 * 1024
	var parts []io.Reader
	for i := 0; i < total/chunk; i++ {
		parts = append(parts, bytes.NewReader(make([]byte, chunk)))
	}
	parts = append(parts, bytes.NewReader([]byte("FAKEIPERF")))
	body := io.NopCloser(io.MultiReader(parts...))
	r := StripH2ClientBootstrapUpload(body)
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(out, []byte("FAKEIPERF")) {
		t.Fatalf("chunked bootstrap: got %q want FAKEIPERF", out)
	}
}

func TestStripH2ClientBootstrapUploadPartialZeroPrefix(t *testing.T) {
	t.Setenv(envH2BidiBootstrapUpload, "4")
	// Less than full bootstrap — not stripped; real iperf would see leading zeros.
	body := io.NopCloser(bytes.NewReader([]byte{0, 0, 'X'}))
	r := StripH2ClientBootstrapUpload(body)
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(out, []byte{0, 0, 'X'}) {
		t.Fatalf("short zero prefix passthrough: %v", out)
	}
}

func TestStripH2ClientBootstrapUploadPassthroughNonZero(t *testing.T) {
	t.Setenv(envH2BidiBootstrapUpload, "4")
	body := io.NopCloser(bytes.NewReader([]byte{1, 2, 3, 4, 'X'}))
	r := StripH2ClientBootstrapUpload(body)
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(out, []byte{1, 2, 3, 4, 'X'}) {
		t.Fatalf("unexpected passthrough: %v", out)
	}
}

func TestStripH2ClientBootstrapUploadDisabled(t *testing.T) {
	t.Setenv(envH2BidiBootstrapUpload, "0")
	body := io.NopCloser(bytes.NewReader([]byte("keep")))
	r := StripH2ClientBootstrapUpload(body)
	if r != body {
		t.Fatal("disabled strip must return original body")
	}
}
