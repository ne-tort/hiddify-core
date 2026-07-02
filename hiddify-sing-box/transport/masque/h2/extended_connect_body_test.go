package h2

import (
	"io"
	"testing"
)

// UploadBootstrapPending reports unconsumed-on-wire pipe bytes (http2 bulk bootstrap gate).
func TestExtendedConnectUploadBodyUploadBootstrapPending(t *testing.T) {
	t.Parallel()
	pr, pw := io.Pipe()
	defer func() { _ = pr.Close() }()
	defer func() { _ = pw.Close() }()
	body := &ExtendedConnectUploadBody{Pipe: pr}
	if body.UploadBootstrapPending() {
		t.Fatal("idle body: bootstrap should not be pending")
	}
	go func() { _, _ = pw.Write([]byte("xy")) }()
	buf := make([]byte, 8)
	_, _ = body.Read(buf)
	if !body.UploadBootstrapPending() {
		t.Fatal("after read before wire ack: bootstrap pending")
	}
	body.MasqueUploadWireAck(2)
	if body.UploadBootstrapPending() {
		t.Fatal("after wire ack caught up: bootstrap not pending")
	}
}

func TestExtendedConnectUploadBodyUploadBulkArmed(t *testing.T) {
	t.Parallel()
	body := &ExtendedConnectUploadBody{}
	body.consumed.Store(uploadBulkArmConsumedMin)
	body.MasqueUploadWireAck(64)
	if !body.UploadBulkArmed() {
		t.Fatal("expected bulk armed after user-payload wire ack")
	}
}

func TestExtendedConnectUploadBodyMasqueUploadBufferedShallowPipe(t *testing.T) {
	t.Parallel()
	pr, pw := NewConnectUploadShallowPipe()
	defer func() { _ = pr.Close() }()
	defer func() { _ = pw.Close() }()
	body := &ExtendedConnectUploadBody{Pipe: pr}
	if got := body.MasqueUploadBuffered(); got != 0 {
		t.Fatalf("idle buffered=%d want 0", got)
	}
	if got := body.UploadPipeCap(); got != connectUploadShallowPipeBuf {
		t.Fatalf("cap=%d want %d", got, connectUploadShallowPipeBuf)
	}
	_, _ = pw.Write([]byte("xy"))
	if got := body.MasqueUploadBuffered(); got != 2 {
		t.Fatalf("after write buffered=%d want 2", got)
	}
}
