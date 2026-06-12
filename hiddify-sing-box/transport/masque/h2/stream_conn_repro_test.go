package h2

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"
)

// TestH2ConnectStreamUploadRepro verifies bulk upload does not stall when download is idle
// (minimal in-proc repro of docker H2 CONNECT-stream upload hang).
func TestH2ConnectStreamUploadRepro(t *testing.T) {
	t.Setenv("MASQUE_CONNECT_STREAM_PIPE_UPLOAD", "1")

	respR, respW := io.Pipe()
	t.Cleanup(func() {
		_ = respR.Close()
		_ = respW.Close()
	})

	uploadR, uploadW := io.Pipe()
	t.Cleanup(func() {
		_ = uploadR.Close()
		_ = uploadW.Close()
	})

	go func() {
		consume := make([]byte, 4*1024)
		for {
			_, err := uploadR.Read(consume)
			if err != nil {
				return
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	conn, err := ConnectTunnelFromResponse(ctx, &http.Response{Body: respR}, uploadW, "127.0.0.1", 9)
	if err != nil {
		t.Fatalf("tunnel: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	// Download half idle (blocked read on empty pipe) while upload runs — docker H2 hang shape.
	uploadDone := make(chan error, 1)
	go func() {
		payload := make([]byte, 256*1024)
		deadline := time.Now().Add(400 * time.Millisecond)
		for time.Now().Before(deadline) {
			if _, err := conn.Write(payload); err != nil {
				uploadDone <- err
				return
			}
		}
		uploadDone <- nil
	}()

	select {
	case err := <-uploadDone:
		if err != nil {
			t.Fatalf("upload: %v", err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("upload blocked >4s while download idle (H2 CONNECT-stream hang)")
	}
}
