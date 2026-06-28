package inttest

// PERF-1b hybrid synth gate: native H3 upload→download on same session (DialContext reference).

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque"
	M "github.com/sagernet/sing/common/metadata"
)

const (
	perf1bHybridUploadDur   = HybridSynthBenchDur
	perf1bHybridDownloadDur = HybridSynthBenchDur
	perf1bHybridSettlePause = 500 * time.Millisecond
	perf1bHybridMinDownMbps = HybridSmokeMinDownMbps
)

// RunGATEConnectIPPerf1bHybridUploadDownloadPair exercises upload then download on one native
// H3 packet session. Guards hybrid flush policy regressions (download dead after bulk upload).
func RunGATEConnectIPPerf1bHybridUploadDownloadPair(t *testing.T) {
	t.Helper()
	uploadLn := masque.StartConnectIPNativeUploadSink(t)
	downLn := StartHybridConnectIPDownloadTarget(t)
	srv := NewHybridConnectIPH3Server(t)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	sess, err := (masque.CoreClientFactory{}).NewSession(ctx, HybridNativeH3ClientOptions(srv.Port()))
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()
	if _, err := sess.OpenIPSession(ctx); err != nil {
		t.Fatalf("OpenIPSession: %v", err)
	}

	upPort := uint16(uploadLn.Addr().(*net.TCPAddr).Port)
	upConn, err := sess.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", upPort))
	if err != nil {
		t.Fatalf("dial upload: %v", err)
	}
	upBytes, upMbps, upErr := masque.MeasureNativeUploadMbps(upConn, perf1bHybridUploadDur)
	_ = upConn.Close()
	if upErr != nil && upBytes == 0 {
		t.Fatalf("upload: %v", upErr)
	}
	t.Logf("perf1b upload: %.1f Mbit/s (%d bytes)", upMbps, upBytes)
	masque.WaitNativeConnectIPEgressSettled(ctx, perf1bHybridSettlePause)

	downPort := uint16(downLn.Addr().(*net.TCPAddr).Port)
	probeConn, err := sess.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", downPort))
	if err != nil {
		t.Fatalf("download probe dial: %v", err)
	}
	_, _ = probeConn.Write([]byte{0x42})
	_ = probeConn.Close()
	t.Log("perf1b download probe OK")
	masque.WaitNativeConnectIPEgressSettled(ctx, perf1bHybridSettlePause)

	downConn, err := sess.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", downPort))
	if err != nil {
		t.Fatalf("dial download: %v", err)
	}
	masque.PrimeNativeTCPDownload(downConn)
	downBytes, downMbps, downErr := masque.MeasureNativeDownloadReadMbps(downConn, perf1bHybridDownloadDur)
	_ = downConn.Close()
	if downErr != nil && downBytes == 0 {
		t.Fatalf("download: %v", downErr)
	}
	t.Logf("perf1b download: %.1f Mbit/s (%d bytes)", downMbps, downBytes)
	if downMbps < perf1bHybridMinDownMbps {
		t.Fatalf("download dead after upload: %.1f Mbit/s want >= %.1f", downMbps, perf1bHybridMinDownMbps)
	}
	minDown := masque.ConnectIPSynthRegressionFloorDownMbps()
	if downMbps < minDown {
		t.Fatalf("download %.1f < regression floor %.1f Mbit/s", downMbps, minDown)
	}
}
