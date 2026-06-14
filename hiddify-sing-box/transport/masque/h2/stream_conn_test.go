package h2

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"
)

func TestH2ConnectStreamConnFromResponse(t *testing.T) {
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
		buf := make([]byte, 256)
		for {
			if _, err := uploadR.Read(buf); err != nil {
				return
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := ConnectTunnelFromResponse(ctx, &http.Response{Body: respR}, uploadW, nil, "127.0.0.1", 443)
	if err != nil {
		t.Fatalf("ConnectTunnelFromResponse: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("upload write: %v", err)
	}
}
