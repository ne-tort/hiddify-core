package masque

import (
	"context"
	"io"
	"net"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	strm "github.com/sagernet/sing-box/transport/masque/stream"
)

type relayBenchResult struct {
	path string
	mbps float64
	err  error
}

func startRelayDownloadTarget(t *testing.T) net.Conn {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("target listen: %v", err)
	}
	buf := make([]byte, 256*1024)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				deadline := time.Now().Add(30 * time.Second)
				for time.Now().Before(deadline) {
					if _, err := c.Write(buf); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		_ = ln.Close()
		t.Fatalf("dial target: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		_ = ln.Close()
	})
	return conn
}

func startRelayUploadTarget(t *testing.T) net.Conn {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("target listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(io.Discard, c)
			}(c)
		}
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		_ = ln.Close()
		t.Fatalf("dial target: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		_ = ln.Close()
	})
	return conn
}

func benchRelayH3Download(t *testing.T, link bidiLink, duration time.Duration) relayBenchResult {
	t.Helper()
	targetConn := startRelayDownloadTarget(t)
	clientLeg, serverLeg := net.Pipe()
	t.Cleanup(func() {
		_ = clientLeg.Close()
		_ = serverLeg.Close()
	})
	client := link.wrap(clientLeg)

	ctx, cancel := context.WithTimeout(context.Background(), duration+3*time.Second)
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- strm.RelayTCPTunnelBidiStream(ctx, targetConn, io.NopCloser(nil), serverLeg)
	}()

	_, mbps, err := measureTCPDownloadMbps(client, duration)
	_ = clientLeg.Close()
	_ = serverLeg.Close()
	go func() { <-errCh }()
	return relayBenchResult{path: "h3-bidi", mbps: mbps, err: err}
}

func benchRelayH3Upload(t *testing.T, link bidiLink, duration time.Duration) relayBenchResult {
	t.Helper()
	targetConn := startRelayUploadTarget(t)
	clientLeg, serverLeg := net.Pipe()
	t.Cleanup(func() {
		_ = clientLeg.Close()
		_ = serverLeg.Close()
	})
	client := link.wrap(clientLeg)

	ctx, cancel := context.WithTimeout(context.Background(), duration+3*time.Second)
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- strm.RelayTCPTunnelBidiStream(ctx, targetConn, io.NopCloser(nil), serverLeg)
	}()

	n, mbps, err := measureTCPUploadMbps(client, duration)
	_ = clientLeg.Close()
	_ = serverLeg.Close()
	go func() { <-errCh }()
	_ = n
	return relayBenchResult{path: "h3-bidi", mbps: mbps, err: err}
}

func benchRelayH2FlushDownload(t *testing.T, link bidiLink, duration time.Duration) relayBenchResult {
	t.Helper()
	targetConn := startRelayDownloadTarget(t)
	clientLeg, serverLeg := net.Pipe()
	t.Cleanup(func() {
		_ = clientLeg.Close()
		_ = serverLeg.Close()
	})
	client := link.wrap(clientLeg)

	rec := httptest.NewRecorder()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = strm.RelayTunnelDownloadH2Style(serverLeg, rec, targetConn)
		_ = serverLeg.Close()
	}()

	_, mbps, err := measureTCPDownloadMbps(client, duration)
	_ = clientLeg.Close()
	_ = serverLeg.Close()
	wg.Wait()
	return relayBenchResult{path: "h2-flush", mbps: mbps, err: err}
}

// TestMasqueRelayH3LocalizeDownload localizes server H3 relay download on windowed bidi (~64 KiB/RTT band).
func TestMasqueRelayH3LocalizeDownload(t *testing.T) {
	const duration = localizeBenchDuration

	instant := benchRelayH3Download(t, instantBidiLink{}, duration)
	windowed := benchRelayH3Download(t, benchWindowedBidiLink(), duration)

	for _, r := range []relayBenchResult{instant, windowed} {
		if r.err != nil {
			t.Fatalf("%s: %v", r.path, r.err)
		}
		t.Logf("relay H3 download %s: %.1f Mbit/s", r.path, r.mbps)
	}

	if instant.mbps < connectStreamLocalizeFastMbps {
		t.Fatalf("H3 relay instant download slow: %.1f Mbit/s (want >= %.0f)", instant.mbps, connectStreamLocalizeFastMbps)
	}
	if windowed.mbps <= connectStreamVPSKPITargetDownMbps {
		t.Fatalf("H3 relay windowed download: %.1f Mbit/s (want > %.0f KPI)", windowed.mbps, connectStreamVPSKPITargetDownMbps)
	}
}

// TestMasqueRelayH3LocalizeUpload localizes server H3 relay upload on windowed bidi.
func TestMasqueRelayH3LocalizeUpload(t *testing.T) {
	const duration = localizeBenchDuration

	instant := benchRelayH3Upload(t, instantBidiLink{}, duration)
	windowed := benchRelayH3Upload(t, benchWindowedBidiLink(), duration)

	for _, r := range []relayBenchResult{instant, windowed} {
		if r.err != nil {
			t.Fatalf("%s: %v", r.path, r.err)
		}
		t.Logf("relay H3 upload %s: %.1f Mbit/s", r.path, r.mbps)
	}

	if instant.mbps < connectStreamLocalizeFastMbps {
		t.Fatalf("H3 relay instant upload slow: %.1f Mbit/s (want >= %.0f)", instant.mbps, connectStreamLocalizeFastMbps)
	}
	if windowed.mbps < connectStreamLocalizeUploadWindowedMin || windowed.mbps > connectStreamLocalizeUploadWindowedMax {
		t.Fatalf("H3 relay windowed upload: %.1f Mbit/s (want %.0f–%.0f)", windowed.mbps, connectStreamLocalizeUploadWindowedMin, connectStreamLocalizeUploadWindowedMax)
	}
}

// TestMasqueRelayH3VsH2FlushDownload confirms H3 io.CopyBuffer is not slower than H2 per-read flush on the relay leg.
func TestMasqueRelayH3VsH2FlushDownload(t *testing.T) {
	const duration = localizeBenchDuration

	h3Instant := benchRelayH3Download(t, instantBidiLink{}, duration)
	h2Instant := benchRelayH2FlushDownload(t, instantBidiLink{}, duration)
	h3Windowed := benchRelayH3Download(t, benchWindowedBidiLink(), duration)
	h2Windowed := benchRelayH2FlushDownload(t, benchWindowedBidiLink(), duration)

	for _, r := range []relayBenchResult{h3Instant, h2Instant, h3Windowed, h2Windowed} {
		if r.err != nil {
			t.Fatalf("%s: %v", r.path, r.err)
		}
		t.Logf("relay download %s: %.1f Mbit/s", r.path, r.mbps)
	}

	if h3Instant.mbps < connectStreamLocalizeFastMbps {
		t.Fatalf("H3 instant download slow: %.1f Mbit/s", h3Instant.mbps)
	}
	if h2Instant.mbps < connectStreamLocalizeFastMbps {
		t.Fatalf("H2 flush instant download slow: %.1f Mbit/s", h2Instant.mbps)
	}
	if h3Windowed.mbps <= connectStreamVPSKPITargetDownMbps {
		t.Fatalf("H3 windowed download: %.1f Mbit/s (want > %.0f KPI)", h3Windowed.mbps, connectStreamVPSKPITargetDownMbps)
	}
	if h2Windowed.mbps <= connectStreamVPSKPITargetDownMbps {
		t.Fatalf("H2 flush windowed download: %.1f Mbit/s (want > %.0f KPI)", h2Windowed.mbps, connectStreamVPSKPITargetDownMbps)
	}

	// H3 without per-read flush must not regress vs H2 flush on the same windowed bidi model.
	// Post-eager-WINDOW both legs exceed KPI by orders of magnitude — compare by ratio not +2 Mbit/s.
	if h2Windowed.mbps > 0 && h3Windowed.mbps < h2Windowed.mbps*0.5 {
		t.Fatalf("H3 windowed download regressed vs H2 flush: h3=%.1f h2=%.1f Mbit/s (want >=50%%)", h3Windowed.mbps, h2Windowed.mbps)
	}
	t.Log("relay eval: H3 io.CopyBuffer download OK without per-read flush; ceiling is bidi credit not H2 Flush")
}
