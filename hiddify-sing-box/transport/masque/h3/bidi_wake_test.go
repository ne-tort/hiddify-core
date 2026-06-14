package h3

import (
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func TestBidiUploadWakeDuringDownloadEnv(t *testing.T) {
	cases := []struct {
		env  string
		want bool
	}{
		{"", true},
		{"1", true},
		{"0", false},
		{"off", true},
	}
	for _, tc := range cases {
		t.Run(tc.env, func(t *testing.T) {
			t.Setenv(envH3BidiUploadWake, tc.env)
			if got := BidiUploadWakeDuringDownload(); got != tc.want {
				t.Fatalf("BidiUploadWakeDuringDownload() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestTunnelConnWakeBidiSendAfterUploadGating(t *testing.T) {
	t.Setenv(envH3BidiUploadWake, "1")
	sink := &bidiWakeRecorder{}
	c := NewTunnelConn(TunnelConnParams{
		H3Stream:     &testH3ConnectStream{},
		BidiWakeSink: sink,
	})

	c.wakeBidiSendAfterUpload()
	if sink.upload.Load() != 0 {
		t.Fatalf("expected no wake without downloadActive, got %d", sink.upload.Load())
	}

	atomic.StoreInt32(&c.downloadActive, 1)
	c.wakeBidiSendAfterUpload()
	if sink.upload.Load() != 1 {
		t.Fatalf("expected wake with downloadActive, got %d", sink.upload.Load())
	}

	t.Setenv(envH3BidiUploadWake, "0")
	c.wakeBidiSendAfterUpload()
	if sink.upload.Load() != 1 {
		t.Fatalf("expected wake disabled by env, got %d", sink.upload.Load())
	}
}

func TestBidiDownloadDeliveryWakeDuringWriteToEnv(t *testing.T) {
	cases := []struct {
		env  string
		want bool
	}{
		{"", true},
		{"1", true},
		{"0", false},
	}
	for _, tc := range cases {
		t.Run(tc.env, func(t *testing.T) {
			t.Setenv(envH3BidiDownloadWake, tc.env)
			if got := BidiDownloadDeliveryWakeDuringWriteTo(); got != tc.want {
				t.Fatalf("BidiDownloadDeliveryWakeDuringWriteTo() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestH3UploadChunkWakePokesCreditSender (H3-T1b-01) — upload chunks during downloadActive
// must reach MasqueWakeBidiDuplex (conn-level), not only MasqueWakeStreamSend.
func TestH3UploadChunkWakePokesCreditSender(t *testing.T) {
	if testing.Short() {
		t.Skip("real QUIC upload wake parity")
	}
	t.Setenv(envH3BidiUploadWake, "1")

	h3RealQuicTLS()
	clientConn, serverConn, closeSimnet := newH3RealQuicSimnetLink(t)
	defer closeSimnet()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	quicCfg := &quic.Config{DisablePathMTUDiscovery: true, MaxIdleTimeout: 2 * time.Minute}
	ln, err := quic.Listen(serverConn, h3RealQuicServerTLS, quicCfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	streamReady := make(chan *quic.Stream, 1)
	go func() {
		conn, err := ln.Accept(ctx)
		if err != nil {
			return
		}
		str, err := conn.OpenStreamSync(ctx)
		if err != nil {
			return
		}
		streamReady <- str
		_, _ = io.Copy(io.Discard, str)
	}()

	conn, err := quic.Dial(ctx, clientConn, serverConn.LocalAddr(), h3RealQuicClientTLS, quicCfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.CloseWithError(0, "")

	select {
	case <-streamReady:
	case <-ctx.Done():
		t.Fatal("timed out waiting for server stream")
	}

	str, err := conn.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("accept stream: %v", err)
	}

	var streamSend, connSend atomic.Int32
	restoreStream := quic.SetMasqueWakeStreamSendHook(func() { streamSend.Add(1) })
	restoreConn := quic.SetMasqueWakeConnSendHook(func() { connSend.Add(1) })
	defer restoreStream()
	defer restoreConn()

	tc := NewTunnelConn(TunnelConnParams{H3Stream: &realQuicH3Stream{Stream: str}, Ctx: ctx})
	atomic.StoreInt32(&tc.downloadActive, 1)
	tc.setBidiDownloadActive(true)

	chunk := make([]byte, 4096)
	if _, err := tc.Write(chunk); err != nil {
		t.Fatalf("upload chunk: %v", err)
	}
	if streamSend.Load() == 0 {
		t.Fatal("expected stream send wake on upload chunk during downloadActive")
	}
	if connSend.Load() == 0 {
		t.Fatal("upload during downloadActive must MasqueWakeBidiDuplex (conn-level wake), not only MasqueWakeStreamSend")
	}
}

func TestTunnelConnWakeBidiSendAfterDownloadDeliveryGating(t *testing.T) {
	t.Setenv(envH3BidiDownloadWake, "1")
	t.Setenv(envH3BidiUploadWake, "0")
	sink := &bidiWakeRecorder{}
	c := NewTunnelConn(TunnelConnParams{
		H3Stream:     &testH3ConnectStream{},
		BidiWakeSink: sink,
	})

	c.wakeBidiSendAfterDownloadDelivery()
	if sink.download.Load() != 0 {
		t.Fatalf("expected no wake without downloadActive, got %d", sink.download.Load())
	}

	atomic.StoreInt32(&c.downloadActive, 1)
	c.wakeBidiSendAfterDownloadDelivery()
	if sink.download.Load() != 1 {
		t.Fatalf("expected wake with downloadActive, got %d", sink.download.Load())
	}

	t.Setenv(envH3BidiDownloadWake, "0")
	c.wakeBidiSendAfterDownloadDelivery()
	if sink.download.Load() != 1 {
		t.Fatalf("expected download wake disabled by env, got %d", sink.download.Load())
	}
}
