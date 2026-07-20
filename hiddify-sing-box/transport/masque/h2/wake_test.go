package h2

import (
	"io"
	"testing"
)

type h2IngressUploadFlushStub struct {
	flushCalls int
}

func (s *h2IngressUploadFlushStub) Write(p []byte) (int, error) {
	return len(p), nil
}

func (s *h2IngressUploadFlushStub) Flush() error {
	s.flushCalls++
	return nil
}

func TestFlushConnectIPIngressAckWakeH2PokesUpload(t *testing.T) {
	t.Parallel()
	upload := &h2IngressUploadFlushStub{}
	FlushConnectIPIngressAckWake(upload)
	if upload.flushCalls != 1 {
		t.Fatalf("FlushConnectIPIngressAckWake must flush upload once, got %d", upload.flushCalls)
	}
}

func TestFlushConnectIPIngressAckWakePrefersPokeH2BidiDownload(t *testing.T) {
	t.Parallel()
	upload := &h2IngressUploadPokeStub{}
	FlushConnectIPIngressAckWake(upload)
	if upload.pokeCalls != 1 {
		t.Fatalf("FlushConnectIPIngressAckWake must PokeH2BidiDownload once, got %d", upload.pokeCalls)
	}
	if upload.flushCalls != 0 {
		t.Fatalf("PokeH2BidiDownload path must not FlushRequestBody, flushes=%d", upload.flushCalls)
	}
}

type h2IngressUploadPokeStub struct {
	h2IngressUploadFlushStub
	pokeCalls int
}

func (s *h2IngressUploadPokeStub) PokeH2BidiDownload() {
	s.pokeCalls++
}

func TestFlushConnectIPIngressAckWakeH2NilUploadSafe(t *testing.T) {
	t.Parallel()
	FlushConnectIPIngressAckWake(nil)
	FlushConnectIPIngressAckWake(io.Discard)
}

func TestFlushRequestBodyFlushError(t *testing.T) {
	t.Parallel()
	upload := &h2IngressUploadFlushStub{}
	FlushRequestBody(upload)
	if upload.flushCalls != 1 {
		t.Fatalf("FlushRequestBody must call Flush() once, got %d", upload.flushCalls)
	}
}

func TestFlushRequestBodyNilSafe(t *testing.T) {
	t.Parallel()
	FlushRequestBody(nil)
	FlushRequestBody(io.Discard)
}

func TestFlushRequestBodyHTTPFlusher(t *testing.T) {
	t.Parallel()
	stub := &h2HTTPFlusherStub{}
	FlushRequestBody(stub)
	if stub.flushCalls != 1 {
		t.Fatalf("FlushRequestBody must call http.Flusher once, got %d", stub.flushCalls)
	}
}

type h2HTTPFlusherStub struct {
	flushCalls int
}

func (s *h2HTTPFlusherStub) Write(p []byte) (int, error) {
	return len(p), nil
}

func (s *h2HTTPFlusherStub) Flush() {
	s.flushCalls++
}
