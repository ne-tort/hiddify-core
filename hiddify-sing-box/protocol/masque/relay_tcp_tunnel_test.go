package masque

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestMasqueRelayUseLegacyFlushRelay(t *testing.T) {
	t.Setenv("MASQUE_RELAY_TCP_LEGACY", "")
	if masqueRelayUseLegacyFlushRelay() {
		t.Fatal("expected tunnel relay by default")
	}
	t.Setenv("MASQUE_RELAY_TCP_LEGACY", "1")
	if !masqueRelayUseLegacyFlushRelay() {
		t.Fatal("expected legacy when MASQUE_RELAY_TCP_LEGACY=1")
	}
}

func TestRelayTCPTunnelDuplex(t *testing.T) {
	t.Parallel()
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(serverConn, bytes.NewReader([]byte("upload-payload")))
		_ = serverConn.Close()
	}()

	rec := httptest.NewRecorder()
	body := io.NopCloser(bytes.NewReader(nil))
	err := relayTCPTunnel(context.Background(), clientConn, body, rec)
	wg.Wait()
	if err != nil && !errorsIsEOF(err) {
		t.Fatalf("relay: %v", err)
	}
	_ = rec
}

func errorsIsEOF(err error) bool {
	return err == nil || errors.Is(err, io.EOF)
}

func TestRelayTCPTunnelDownloadToResponse(t *testing.T) {
	t.Parallel()
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	go func() {
		_, _ = serverConn.Write([]byte("hello-from-target"))
		_ = serverConn.Close()
	}()

	rec := httptest.NewRecorder()
	reqBody := io.NopCloser(bytes.NewReader(nil))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := relayTCPTunnel(ctx, clientConn, reqBody, rec)
	if err != nil && !errorsIsEOF(err) {
		t.Fatalf("relay: %v", err)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("hello-from-target")) {
		t.Fatalf("response body=%q", rec.Body.Bytes())
	}
}
