package masque

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque/h3"
	strm "github.com/sagernet/sing-box/transport/masque/stream"
)

// TestMasqueConnectStreamLocalizeRecycle verifies bulk upload teardown on one CONNECT-stream
// tunnel does not poison the shared MASQUE session before a fresh download flow (S45).
func TestMasqueConnectStreamLocalizeRecycle(t *testing.T) {
	const uploadDur = 300 * time.Millisecond
	const downloadDur = localizeBenchDuration

	pool := startConnectStreamParallelPool(t, instantBidiLink{})
	defer pool.close()

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	upConn, err := pool.dial(ctx)
	if err != nil {
		t.Fatalf("dial upload: %v", err)
	}
	upBytes, upMbps, err := measureTCPUploadMbps(upConn, uploadDur)
	if err != nil {
		t.Fatalf("upload bench: %v", err)
	}
	if err := upConn.Close(); err != nil {
		t.Fatalf("close upload conn: %v", err)
	}
	waitConnectStreamRecycleReady(t, pool)

	downConn, err := pool.dial(ctx)
	if err != nil {
		t.Fatalf("dial download after recycle: %v", err)
	}
	defer downConn.Close()
	downBytes, downMbps, err := measureTCPDownloadWriteToMbps(downConn, downloadDur)
	if err != nil {
		t.Fatalf("download bench after recycle: %v", err)
	}
	t.Logf("connect-stream recycle upload: %.1f Mbit/s (%d bytes)", upMbps, upBytes)
	t.Logf("connect-stream recycle download WriteTo: %.1f Mbit/s (%d bytes)", downMbps, downBytes)
	if downMbps < connectStreamLocalizeFastMbps {
		t.Fatalf("download after upload recycle slow: %.1f Mbit/s (want >= %.0f)", downMbps, connectStreamLocalizeFastMbps)
	}
}

// TestH3DuplexConnWakeReceiveVsDeliveryEnvMatrix (S64): upload vs download BidiWakeSink events
// on full CONNECT-stream harness under MASQUE_H3_BIDI_UPLOAD_WAKE env.
func TestH3DuplexConnWakeReceiveVsDeliveryEnvMatrix(t *testing.T) {
	cases := []struct {
		name      string
		wake      string
		wantWakes bool
	}{
		{"wake_on", "1", true},
		{"wake_off", "0", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("MASQUE_H3_BIDI_DUPLEX_COORD", "1")
			t.Setenv("MASQUE_H3_BIDI_UPLOAD_WAKE", tc.wake)
			t.Setenv("MASQUE_H3_BIDI_DOWNLOAD_WAKE", tc.wake)

			inj := newLocalizeInjectors()
			dl := runConnectStreamDuplexWriteToBench(
				t,
				benchWindowedBidiLink(),
				connectStreamLocalizeDownloadKPIMin,
				inj.connectStreamOpts(),
			)
			assertConnectStreamWindowedCeilingBand(t, dl.mbps, "duplex WriteTo download (S64 wake matrix)")

			uploadWakes := inj.BidiWake.Upload.Load()
			downloadWakes := inj.BidiWake.Download.Load()
			t.Logf("duplex wake matrix wake=%s upload=%d download=%d", tc.wake, uploadWakes, downloadWakes)

			if tc.wantWakes {
				if uploadWakes == 0 {
					t.Fatal("expected upload-side BidiWakeSink events with wake env on")
				}
				if downloadWakes == 0 {
					t.Fatal("expected download-delivery BidiWakeSink events with wake env on")
				}
				return
			}
			if uploadWakes != 0 || downloadWakes != 0 {
				t.Fatalf("expected no BidiWakeSink events with wake env off, upload=%d download=%d", uploadWakes, downloadWakes)
			}
		})
	}
}

// TestConnectStreamLocalizeH3WakeAndFlushMetrics (S42): windowed CONNECT-stream download records
// BidiWakeSink delivery events and meets localize bench byte/Mbps contract under wake env.
func TestConnectStreamLocalizeH3WakeAndFlushMetrics(t *testing.T) {
	t.Setenv("MASQUE_H3_BIDI_DUPLEX_COORD", "1")
	t.Setenv("MASQUE_H3_BIDI_UPLOAD_WAKE", "1")

	inj := newLocalizeInjectors()
	h := startConnectStreamDownloadHarness(t, benchWindowedBidiLink(), inj.connectStreamOpts())
	defer h.close()

	n, mbps, err := measureTCPDownloadWriteToMbps(h.conn, localizeBenchDuration)
	if err != nil {
		t.Fatalf("windowed WriteTo download: %v", err)
	}
	if n < localizeBenchMinBytes {
		t.Fatalf("bytes=%d want >= %d", n, localizeBenchMinBytes)
	}
	assertConnectStreamWindowedCeilingBand(t, mbps, "download WriteTo (S42)")

	downloadWakes := inj.BidiWake.Download.Load()
	t.Logf("connect-stream H3 wake metrics: downloadWakes=%d bytes=%d mbps=%.1f", downloadWakes, n, mbps)
	if downloadWakes == 0 {
		t.Fatal("expected download BidiWakeSink events with MASQUE_H3_BIDI_UPLOAD_WAKE=1")
	}
}

// unwrapH3TunnelConn walks masque wrappers to the underlying *h3.TunnelConn.
func unwrapH3TunnelConn(conn net.Conn) (*h3.TunnelConn, bool) {
	for conn != nil {
		if tc, ok := conn.(*h3.TunnelConn); ok {
			return tc, true
		}
		switch c := conn.(type) {
		case *strm.TunnelConn:
			conn = c.Inner
		default:
			if inner, ok := h3.BidiWindowInner(conn); ok {
				conn = inner
			} else {
				return nil, false
			}
		}
	}
	return nil, false
}

// TestMasqueConnectStreamBidiLocalizeDownload (S89) guards bidi stream upload under windowed credit.
func TestMasqueConnectStreamBidiLocalizeDownload(t *testing.T) {
	t.Run("bidi_uses_h3_stream_windowed_ceiling", func(t *testing.T) {
		h := startConnectStreamDownloadHarness(t, benchWindowedBidiLink())
		defer h.close()
		tc, ok := unwrapH3TunnelConn(h.conn)
		if !ok {
			t.Fatal("expected *h3.TunnelConn under harness conn")
		}
		if !tc.UsesH3Stream() {
			t.Fatal("bidi mode must share one http3.Stream (UsesH3Stream=true)")
		}
		dl := runConnectStreamDuplexWriteToBenchOnConn(t, h.conn, connectStreamLocalizeDownloadKPIMin/2)
		assertConnectStreamWindowedCeilingBand(t, dl.mbps, "bidi windowed duplex WriteTo")
	})
}

// TestMasqueConnectStreamHypothesisHD1DuplexQuota (S91) guards the thin WriteTo path without
// removed H-D1 duplex quota: instant download exceeds VPS KPI; windowed duplex stays in ceiling band.
func TestMasqueConnectStreamHypothesisHD1DuplexQuota(t *testing.T) {
	t.Setenv("MASQUE_H3_BIDI_DUPLEX_COORD", "1")

	instant := benchConnectStreamDownloadLayerWriteTo(t, "L1", instantBidiLink{}, localizeBenchDuration)
	if instant.err != nil {
		t.Fatalf("instant WriteTo download: %v", instant.err)
	}
	t.Logf("H-D1 guard instant WriteTo: %.1f Mbit/s", instant.mbps)
	if instant.mbps <= connectStreamVPSKPITargetDownMbps {
		t.Fatalf("without duplex quota instant download %.1f Mbit/s (want > %.0f VPS KPI)", instant.mbps, connectStreamVPSKPITargetDownMbps)
	}

	windowed := benchConnectStreamDownloadLayerWriteTo(t, "L3", benchWindowedBidiLink(), localizeBenchDuration)
	if windowed.err != nil {
		t.Fatalf("windowed WriteTo download: %v", windowed.err)
	}
	t.Logf("H-D1 guard windowed WriteTo: %.1f Mbit/s", windowed.mbps)
	if windowed.mbps <= connectStreamVPSKPITargetDownMbps {
		t.Fatalf("windowed ceiling without quota: %.1f Mbit/s (want > %.0f — quota was not root cause)", windowed.mbps, connectStreamVPSKPITargetDownMbps)
	}

	duplex := runConnectStreamDuplexWriteToBench(t, benchWindowedBidiLink(), connectStreamLocalizeDownloadKPIMin/2)
	t.Logf("H-D1 guard duplex WriteTo: %.1f Mbit/s", duplex.mbps)
}
