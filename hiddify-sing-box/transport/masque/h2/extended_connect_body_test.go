package h2

import (
	"io"
	"testing"
	"time"
)

func TestExtendedConnectUploadBodyAwaitConsumed(t *testing.T) {
	pr, pw := io.Pipe()
	t.Cleanup(func() {
		_ = pw.Close()
		_ = pr.Close()
	})
	body := &ExtendedConnectUploadBody{Pipe: pr}
	go func() {
		time.Sleep(20 * time.Millisecond)
		body.MasqueUploadWireAck(4096)
	}()
	if err := body.AwaitUploadConsumed(4096, time.Second); err != nil {
		t.Fatalf("AwaitUploadConsumed: %v", err)
	}
}

func TestH2ExtendedConnectUploadBodyCloseIsNoop(t *testing.T) {
	pr, pw := io.Pipe()
	t.Cleanup(func() {
		_ = pw.Close()
		_ = pr.Close()
	})
	body := &ExtendedConnectUploadBody{Pipe: pr}
	if err := body.Close(); err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = pw.Write([]byte{'x'}) }()
	buf := make([]byte, 1)
	n, err := body.Read(buf)
	if err != nil || n != 1 || buf[0] != 'x' {
		t.Fatalf("Read after Body.Close noop: n=%d err=%v buf=%q", n, err, buf[:n])
	}
}
