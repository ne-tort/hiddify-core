package masque

// Pure h2o-shaped server relay benchmarks (not prod relay.go env toggles).

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

const refH2oRelayBufLen = 64 * 1024

var refH2oRelayBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, refH2oRelayBufLen)
		return &b
	},
}

// refH2oRelayBidi is a minimal h2o proxy.tunnel relay: two goroutines, io.CopyBuffer 64 KiB, no batched wake/prime.
func refH2oRelayBidi(ctx context.Context, targetConn net.Conn, uploadSrc io.Reader, bidiLeg io.Writer) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	uploadErrCh := make(chan error, 1)
	downloadErrCh := make(chan error, 1)

	go func() {
		buf := refH2oRelayBufPool.Get().(*[]byte)
		defer refH2oRelayBufPool.Put(buf)
		_, err := io.CopyBuffer(targetConn, uploadSrc, *buf)
		uploadErrCh <- err
	}()

	go func() {
		buf := refH2oRelayBufPool.Get().(*[]byte)
		defer refH2oRelayBufPool.Put(buf)
		_, err := io.CopyBuffer(bidiLeg, targetConn, *buf)
		downloadErrCh <- err
	}()

	select {
	case err := <-uploadErrCh:
		cancel()
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		select {
		case err := <-downloadErrCh:
			if err != nil && !errors.Is(err, io.EOF) {
				return err
			}
		case <-ctx.Done():
		}
	case err := <-downloadErrCh:
		cancel()
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		select {
		case err := <-uploadErrCh:
			if err != nil && !errors.Is(err, io.EOF) {
				return err
			}
		case <-ctx.Done():
		}
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

func benchRefH2oRelayDownloadMbps(t *testing.T, duration time.Duration) (int64, float64) {
	t.Helper()
	targetConn := startRelayDownloadTarget(t)
	clientLeg, serverLeg := net.Pipe()
	uploadR, uploadW := io.Pipe()
	t.Cleanup(func() {
		_ = uploadW.Close()
		_ = uploadR.Close()
		_ = clientLeg.Close()
		_ = serverLeg.Close()
	})

	go func() {
		_, _ = io.Copy(io.Discard, uploadR)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), duration+3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- refH2oRelayBidi(ctx, targetConn, uploadR, serverLeg)
	}()

	n, mbps, err := measureRelayHijackDownloadMbps(clientLeg, duration)
	cancel()
	_ = uploadW.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
	if err != nil && n == 0 {
		t.Fatalf("ref-h2o relay download: %v", err)
	}
	return n, mbps
}

func benchProdH2oEnvRelayDownloadMbps(t *testing.T, duration time.Duration) (int64, float64) {
	t.Helper()
	t.Setenv("MASQUE_RELAY_TCP_BATCHED_DUPLEX_WAKE", "0")
	t.Setenv("MASQUE_RELAY_TCP_SKIP_PRIME", "1")
	t.Setenv("MASQUE_RELAY_TCP_STREAM_HIJACK", "1")
	setup := func(tb *testing.T) (net.Conn, http.ResponseWriter, func()) {
		return startRelayDownloadTarget(tb), &mockH3RelayResponse{}, func() {}
	}
	return benchRelayTCPTunnelDownload(t, relayInstantLink{}, setup)
}
