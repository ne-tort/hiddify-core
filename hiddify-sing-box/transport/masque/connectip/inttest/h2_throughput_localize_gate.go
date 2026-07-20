//go:build masque_inttest_heavy

package inttest

// P6-D1-H2-LOCALIZE: reproduce ~300 Mbit/s H2 TCP ceiling in-proc (no Docker) and compare H3.

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque"
	M "github.com/sagernet/sing/common/metadata"
)

const (
	h2LocalizeBenchDur      = NativeSynthBenchDur
	h2LocalizeMinBytes      = 8 * 1024 * 1024 // 8 MiB in 2s => ~32 Mbit/s minimum sanity
	h2LocalizeH2DownFloor   = 250.0           // in-proc/docker H2 download band floor
	h2LocalizeH2DownCeiling = 420.0           // in-proc/docker H2 download band ceiling
	h2LocalizeH3DownFloor     = 500.0           // H3 in-proc should be well above H2 on same host
	h2LocalizeMaxH2H3DownRatio = 0.55          // H2/H3 download — structural gap localize (Docker ~0.35)
	h2LocalizeCPUNsPerBOpen   = 25.0            // ns/B above this => CPU-saturated band (~320 Mbps ceiling)
)

type h2LocalizeResult struct {
	Layer    string
	Upload   ThroughputSample
	Download ThroughputSample
}

// RunGATEConnectIPH2ThroughputLocalize measures H2 vs H3 native upload/download with CPU ns/byte.
func RunGATEConnectIPH2ThroughputLocalize(t *testing.T) {
	t.Helper()
	h2 := runConnectIPThroughputLegs(t, "h2", StartNativeConnectIPH2Server, NativeH2ClientOptions)
	h3 := runConnectIPThroughputLegs(t, "h3", StartNativeConnectIPH3Server, NativeH3ClientOptions)
	logAndAnalyzeH2Localize(t, h2, h3)
}

func runConnectIPThroughputLegs(
	t *testing.T,
	layer string,
	startServer func(testing.TB) int,
	clientOpts func(int) masque.ClientOptions,
) h2LocalizeResult {
	t.Helper()
	uploadLn := masque.StartConnectIPNativeUploadSink(t)
	downloadLn := StartNativeConnectIPDownloadTarget(t)
	proxyPort := startServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sess, err := (masque.CoreClientFactory{}).NewSession(ctx, clientOpts(proxyPort))
	if err != nil {
		t.Fatalf("%s session: %v", layer, err)
	}
	defer sess.Close()
	if _, err := sess.OpenIPSession(ctx); err != nil {
		t.Fatalf("%s OpenIPSession: %v", layer, err)
	}

	uploadAddr := M.ParseSocksaddrHostPort("127.0.0.1", uint16(uploadLn.Addr().(*net.TCPAddr).Port))
	downloadAddr := M.ParseSocksaddrHostPort("127.0.0.1", uint16(downloadLn.Addr().(*net.TCPAddr).Port))

	upConn, err := sess.DialContext(ctx, "tcp", uploadAddr)
	if err != nil {
		t.Fatalf("%s upload dial: %v", layer, err)
	}
	defer upConn.Close()
	up := measureUploadSample(layer, "upload", upConn, h2LocalizeBenchDur)

	downConn, err := sess.DialContext(ctx, "tcp", downloadAddr)
	if err != nil {
		t.Fatalf("%s download dial: %v", layer, err)
	}
	defer downConn.Close()
	masque.PrimeNativeTCPDownload(downConn)
	down := measureDownloadSample(layer, "download", downConn, h2LocalizeBenchDur)

	return h2LocalizeResult{Layer: layer, Upload: up, Download: down}
}

func logAndAnalyzeH2Localize(t *testing.T, h2, h3 h2LocalizeResult) {
	t.Helper()
	for _, r := range []h2LocalizeResult{h2, h3} {
		t.Logf("LOCALIZE %s", r.Upload)
		t.Logf("LOCALIZE %s", r.Download)
		for _, s := range []ThroughputSample{r.Upload, r.Download} {
			if s.Bytes < h2LocalizeMinBytes {
				t.Fatalf("%s %s too small: %d bytes want >= %d (dead path?)", s.Layer, s.Leg, s.Bytes, h2LocalizeMinBytes)
			}
		}
	}

	ratioUp := h2.Upload.Mbps / h3.Upload.Mbps
	ratioDown := h2.Download.Mbps / h3.Download.Mbps
	t.Logf("LOCALIZE H2/H3 ratio upload=%.2f download=%.2f (H2 up=%.1f down=%.1f | H3 up=%.1f down=%.1f)",
		ratioUp, ratioDown, h2.Upload.Mbps, h2.Download.Mbps, h3.Upload.Mbps, h3.Download.Mbps)

	// Primary localize signal: H2 download band (~280–380 Docker parity on Windows/Linux in-proc).
	if h2.Download.Mbps < h2LocalizeH2DownFloor || h2.Download.Mbps > h2LocalizeH2DownCeiling {
		t.Fatalf("H2 download %.1f outside localize band [%.0f, %.0f] (dead path or gap closed?)",
			h2.Download.Mbps, h2LocalizeH2DownFloor, h2LocalizeH2DownCeiling)
	}
	if ratioDown > h2LocalizeMaxH2H3DownRatio {
		t.Fatalf("H2/H3 download ratio %.2f > %.2f — structural gap not reproduced (regression?)",
			ratioDown, h2LocalizeMaxH2H3DownRatio)
	}
	if h3.Download.Mbps < h2LocalizeH3DownFloor {
		t.Logf("WARN: H3 download %.1f below floor %.0f — host variance; H2 band still valid",
			h3.Download.Mbps, h2LocalizeH3DownFloor)
	}

	for _, s := range []ThroughputSample{h2.Download, h2.Upload} {
		if s.NsPerByte >= h2LocalizeCPUNsPerBOpen {
			t.Logf("LOCALIZE CPU-saturated band: %s %s ns/B=%.1f => cpu_ceil≈%.0f Mbit/s (observed %.1f)",
				s.Layer, s.Leg, s.NsPerByte, s.CPUCeilingMbps, s.Mbps)
		} else {
			t.Logf("LOCALIZE not CPU-only bound: %s %s ns/B=%.1f observed %.1f (sched/FC/wire tax likely)",
				s.Layer, s.Leg, s.NsPerByte, s.Mbps)
		}
	}
	t.Logf("LOCALIZE PASS: H2 download ceiling reproduced (ratio=%.2f band=[%.0f,%.0f])",
		ratioDown, h2LocalizeH2DownFloor, h2LocalizeH2DownCeiling)
}
