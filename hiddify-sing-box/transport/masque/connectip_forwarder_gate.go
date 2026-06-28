package masque

// CONNECT-IP forwarder gate implementations (W-IP-6 IP-6-PR3 inttest export).

import (
	"bytes"
	"io"
	"testing"
	"time"

	fwd "github.com/sagernet/sing-box/transport/masque/forwarder"
)

func gateConnectIPTCPForwarderPipeSYNHandshake(t *testing.T) {
	h := startForwarderPipeHarness(t, forwarderPipeLink{}, true)
	defer h.close()

	conn := h.dialRemote(t)
	defer conn.Close()

	msg := []byte("connect-ip-forwarder-syn")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(buf, msg) {
		t.Fatalf("echo mismatch: got %q want %q", buf, msg)
	}
}

func gateConnectIPTCPForwarderDownloadWindowedLinkThroughput(t *testing.T) {
	var metrics fwd.WriteQueueMetrics
	h := startConnectIPDownloadHarness(t, benchWindowedPacketLink(), connectIPUploadHarnessOpts{WriteQueueMetrics: &metrics})
	defer h.close()

	conn := h.dialRemote(t)
	defer conn.Close()

	n, mbps, err := measureTCPDownloadMbps(conn, 800*time.Millisecond)
	if err != nil {
		t.Fatalf("windowed download: %v", err)
	}
	if n < 8*1024 {
		t.Fatalf("windowed download=%d bytes too small", n)
	}
	depthHigh := metrics.DepthHigh.Load()
	t.Logf("forwarder download windowed: %.1f Mbit/s (%d bytes) writeCh depthHigh=%d",
		mbps, n, depthHigh)
	if depthHigh > 1 {
		t.Fatalf("download DATA writeCh depthHigh=%d want <= 1 (ACK-only on queue)", depthHigh)
	}
	const windowedDownloadMbpsFloor = 0.2
	if mbps < windowedDownloadMbpsFloor {
		t.Fatalf("windowed download %.1f Mbit/s want >= %.1f", mbps, windowedDownloadMbpsFloor)
	}
}

func gateConnectIPTCPForwarderPipeUploadThenDownload(t *testing.T) {
	h := startConnectIPDownloadHarness(t, instantPacketLink{})
	defer h.close()

	upConn := h.dialRemote(t)
	upBytes, upMbps, err := measureTCPUploadMbps(upConn, 300*time.Millisecond)
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	if err := upConn.Close(); err != nil {
		t.Fatalf("close upload conn: %v", err)
	}
	flushConnectIPEgressAfterClose(h)

	downConn := h.dialRemote(t)
	defer downConn.Close()
	downBytes, downMbps, err := measureTCPDownloadMbps(downConn, 400*time.Millisecond)
	if err != nil {
		t.Fatalf("download after upload: %v", err)
	}
	t.Logf("forwarder pipe upload: %.1f Mbit/s (%d bytes)", upMbps, upBytes)
	t.Logf("forwarder pipe download: %.1f Mbit/s (%d bytes)", downMbps, downBytes)
	if downBytes < 32*1024 {
		t.Fatalf("download after upload=%d bytes want >= 32KiB without server restart", downBytes)
	}
}

func gateConnectIPTunForwarderPostUploadServerRecycle(t *testing.T) {
	const (
		uploadDur    = 2 * time.Second
		downloadDur  = 400 * time.Millisecond
		recyclePause = 50 * time.Millisecond
	)
	h := startConnectIPDownloadHarness(t, instantPacketLink{})
	defer h.close()

	upConn := h.dialRemote(t)
	upBytes, upMbps, err := measureTCPUploadMbps(upConn, uploadDur)
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	if err := upConn.Close(); err != nil {
		t.Fatalf("close upload: %v", err)
	}
	flushConnectIPEgressAfterClose(h)
	t.Logf("pre-recycle upload: %.1f Mbit/s (%d bytes)", upMbps, upBytes)

	if err := h.restartForwarder(t); err != nil {
		t.Fatalf("restart forwarder: %v", err)
	}
	time.Sleep(recyclePause)

	probe := h.dialRemote(t)
	if _, err := probe.Write([]byte{0x42}); err != nil {
		t.Fatalf("download TCP probe write after recycle: %v", err)
	}
	_ = probe.Close()

	downConn := h.dialRemote(t)
	defer downConn.Close()
	downBytes, downMbps, err := measureTCPDownloadMbps(downConn, downloadDur)
	if err != nil {
		t.Fatalf("download after forwarder recycle: %v", err)
	}
	t.Logf("post-recycle download: %.1f Mbit/s (%d bytes)", downMbps, downBytes)
	if downMbps < connectIPLocalizeFastMbps {
		t.Fatalf("download after forwarder recycle %.1f Mbit/s want >= %.0f (post-server-restart analog)",
			downMbps, connectIPLocalizeFastMbps)
	}
	if downBytes < 32*1024 {
		t.Fatalf("download after forwarder recycle=%d bytes want >= 32KiB", downBytes)
	}
}
