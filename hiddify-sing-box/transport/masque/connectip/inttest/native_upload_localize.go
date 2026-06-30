//go:build masque_inttest_heavy

package inttest

// Native H3 upload localize gates (W-IP-7 IP-TEST-09). In-proc server harness in harness.go.

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque"
	M "github.com/sagernet/sing/common/metadata"
)

// BenchConnectIPNativeUploadH3 measures upload-only on native H3 connect_ip session.
func BenchConnectIPNativeUploadH3(t *testing.T, duration time.Duration) (float64, int64) {
	t.Helper()
	uploadLn := masque.StartConnectIPNativeUploadSink(t)
	proxyPort := StartNativeConnectIPH3Server(t)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	session, err := (masque.CoreClientFactory{}).NewSession(ctx, NativeH3ClientOptions(proxyPort))
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer session.Close()
	if _, err := session.OpenIPSession(ctx); err != nil {
		t.Fatalf("OpenIPSession: %v", err)
	}

	upPort := uint16(uploadLn.Addr().(*net.TCPAddr).Port)
	upConn, err := session.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", upPort))
	if err != nil {
		t.Fatalf("dial upload: %v", err)
	}
	defer upConn.Close()

	bytes, mbps, err := masque.MeasureNativeUploadMbps(upConn, duration)
	if err != nil {
		t.Logf("native upload ended: %v", err)
	}
	return mbps, bytes
}

// RunLocalizeConnectIPUploadNativeConcurrentDownloadPollution localizes upload under background download.
func RunLocalizeConnectIPUploadNativeConcurrentDownloadPollution(t *testing.T) {
	t.Helper()
	pipeBaseline := masque.BenchConnectIPUploadInstantL1(t, masque.LocalizeBenchDuration)
	if pipeBaseline.Err != nil {
		t.Fatalf("pipe L1 baseline: %v", pipeBaseline.Err)
	}

	uploadLn := masque.StartConnectIPNativeUploadSink(t)
	downLn := StartNativeConnectIPDownloadTarget(t)
	proxyPort := StartNativeConnectIPH3Server(t)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	session, err := (masque.CoreClientFactory{}).NewSession(ctx, NativeH3ClientOptions(proxyPort))
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer session.Close()
	if _, err := session.OpenIPSession(ctx); err != nil {
		t.Fatalf("OpenIPSession: %v", err)
	}

	upPort := uint16(uploadLn.Addr().(*net.TCPAddr).Port)
	upAddr := M.ParseSocksaddrHostPort("127.0.0.1", upPort)
	upConn, err := session.DialContext(ctx, "tcp", upAddr)
	if err != nil {
		t.Fatalf("dial upload: %v", err)
	}

	downPort := uint16(downLn.Addr().(*net.TCPAddr).Port)
	downConn, err := session.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", downPort))
	if err != nil {
		_ = upConn.Close()
		t.Fatalf("dial download: %v", err)
	}
	downDone := make(chan struct{})
	go func() {
		defer close(downDone)
		_, _, _ = masque.MeasureNativeDownloadReadMbps(downConn, masque.ConnectIPNativeSynthBenchDur)
		_ = downConn.Close()
	}()

	upBytes, pollutedMbps, upErr := masque.MeasureNativeUploadMbps(upConn, masque.ConnectIPNativeSynthBenchDur)
	_ = upConn.Close()
	<-downDone

	if upErr != nil && upBytes == 0 {
		t.Fatalf("upload: %v", upErr)
	}

	ratio := pollutedMbps / pipeBaseline.Mbps
	t.Logf("concurrent download pollution: pipe=%.1f upload=%.1f ratio=%.2f", pipeBaseline.Mbps, pollutedMbps, ratio)
	t.Logf("hint: %s", masque.ConnectIPUploadNativeHint(pipeBaseline.Mbps, pollutedMbps))

	const pollutionCollapseRatio = 0.15
	if ratio < pollutionCollapseRatio {
		t.Logf("OPEN: concurrent download starves upload (ratio %.2f) — datagram scheduler / shared conn FC; Docker uses sequential legs", ratio)
	}
	const pollutionMinRatio = 0.50
	if ratio < pollutionMinRatio {
		t.Logf("OPEN: concurrent download pollution ratio %.2f < %.2f — datagram scheduler / shared conn FC; Docker uses sequential legs", ratio, pollutionMinRatio)
	}
	if pollutedMbps >= masque.ConnectIPSynthRegressionFloorUpMbps {
		t.Logf("upload holds regression floor under concurrent download (%.1f Mbps)", pollutedMbps)
	}
}

// RunLocalizeConnectIPUploadNativeDownloadFirstOrder localizes upload after saturated download leg.
func RunLocalizeConnectIPUploadNativeDownloadFirstOrder(t *testing.T) {
	t.Helper()
	uploadOnlyMbps, _ := BenchConnectIPNativeUploadH3(t, masque.ConnectIPNativeSynthBenchDur)

	uploadLn := masque.StartConnectIPNativeUploadSink(t)
	downLn := StartNativeConnectIPDownloadTarget(t)
	proxyPort := StartNativeConnectIPH3Server(t)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()

	session, err := (masque.CoreClientFactory{}).NewSession(ctx, NativeH3ClientOptions(proxyPort))
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer session.Close()
	if _, err := session.OpenIPSession(ctx); err != nil {
		t.Fatalf("OpenIPSession: %v", err)
	}

	downPort := uint16(downLn.Addr().(*net.TCPAddr).Port)
	downConn, err := session.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", downPort))
	if err != nil {
		t.Fatalf("dial download: %v", err)
	}
	_, _, _ = masque.MeasureNativeDownloadReadMbps(downConn, masque.ConnectIPNativeSynthBenchDur)
	_ = downConn.Close()

	upPort := uint16(uploadLn.Addr().(*net.TCPAddr).Port)
	uploadDialCtx, uploadDialCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer uploadDialCancel()
	upConn, err := session.DialContext(uploadDialCtx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", upPort))
	if err != nil {
		t.Logf("OPEN: upload dial after saturated download failed: %v — shared-session second native TCP leg (see TestGATEConnectIPNativeH3OrderSensitivity)", err)
		return
	}
	upBytes, afterDownMbps, upErr := masque.MeasureNativeUploadMbps(upConn, masque.ConnectIPNativeSynthBenchDur)
	_ = upConn.Close()
	if upErr != nil && upBytes == 0 {
		t.Fatalf("upload after download: %v", upErr)
	}

	ratio := afterDownMbps / uploadOnlyMbps
	t.Logf("download-first order: upload-only=%.1f after-download=%.1f ratio=%.2f", uploadOnlyMbps, afterDownMbps, ratio)
	if afterDownMbps < masque.ConnectIPSynthRegressionFloorUpMbps {
		t.Fatalf("upload after download regression: %.1f < %.1f", afterDownMbps, masque.ConnectIPSynthRegressionFloorUpMbps)
	}
	const orderCollapseRatio = 0.50
	if ratio < orderCollapseRatio {
		t.Logf("OPEN: download-first collapses upload (ratio %.2f) — not Docker connect-ip-h3-tun order but shared-session state", ratio)
	}
}
