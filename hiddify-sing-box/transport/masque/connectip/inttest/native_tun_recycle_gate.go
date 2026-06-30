//go:build masque_inttest_heavy

package inttest

// Native H3 TUN recycle synth (W-IP-TUN IP-TUN-PR4). Mirrors Docker connect-ip-h3-tun phase order without OS tun0.

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque"
	M "github.com/sagernet/sing/common/metadata"
)

const (
	tunRecycleUploadDur    = masque.ConnectIPNativeSynthBenchDur
	tunRecycleDownloadDur  = masque.ConnectIPNativeSynthBenchDur
	tunRecyclePreflightMin = 1.0 // Mbit/s — parity BENCH_CONNECT_IP_TUN_PROBE_MIN_MBIT
)

// RunGATEConnectIPTunNativeH3PostUploadServerRecycleDownload mirrors Docker:
// upload → restart server → fresh client → download preflight.
func RunGATEConnectIPTunNativeH3PostUploadServerRecycleDownload(t *testing.T) {
	t.Helper()
	uploadLn := masque.StartConnectIPNativeUploadSink(t)
	downLn := StartNativeConnectIPDownloadTarget(t)
	srv := NewNativeConnectIPH3Server(t)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	sessA, err := (masque.CoreClientFactory{}).NewSession(ctx, NativeH3ClientOptions(srv.Port()))
	if err != nil {
		t.Fatalf("session A: %v", err)
	}
	if _, err := sessA.OpenIPSession(ctx); err != nil {
		_ = sessA.Close()
		t.Fatalf("OpenIPSession A: %v", err)
	}
	upPort := uint16(uploadLn.Addr().(*net.TCPAddr).Port)
	upConn, err := sessA.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", upPort))
	if err != nil {
		_ = sessA.Close()
		t.Fatalf("dial upload: %v", err)
	}
	upBytes, upMbps, upErr := masque.MeasureNativeUploadMbps(upConn, tunRecycleUploadDur)
	_ = upConn.Close()
	_ = sessA.Close()
	if upErr != nil && upBytes == 0 {
		t.Fatalf("upload: %v", upErr)
	}
	t.Logf("pre-recycle native upload: %.1f Mbit/s (%d bytes)", upMbps, upBytes)
	masque.WaitNativeConnectIPEgressSettled(ctx, tunRecycleRacePause)

	_ = downLn.Close()
	downLn = StartNativeConnectIPDownloadTarget(t)

	srv.Restart(t)
	masque.WaitNativeConnectIPEgressSettled(ctx, tunRecycleRacePause)

	sessB, err := (masque.CoreClientFactory{}).NewSession(ctx, NativeH3ClientOptions(srv.Port()))
	if err != nil {
		t.Fatalf("session B: %v", err)
	}
	defer sessB.Close()
	if _, err := sessB.OpenIPSession(ctx); err != nil {
		t.Fatalf("OpenIPSession B: %v", err)
	}

	downPort := uint16(downLn.Addr().(*net.TCPAddr).Port)
	probeConn, err := sessB.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", downPort))
	if err != nil {
		t.Fatalf("download TCP probe dial: %v", err)
	}
	if _, err := probeConn.Write([]byte{0x42}); err != nil {
		_ = probeConn.Close()
		t.Fatalf("download TCP probe write: %v", err)
	}
	_ = probeConn.Close()
	masque.WaitNativeConnectIPEgressSettled(ctx, 200*time.Millisecond)

	downConn, err := sessB.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", downPort))
	if err != nil {
		t.Fatalf("dial download: %v", err)
	}
	masque.PrimeNativeTCPDownload(downConn)
	downBytes, downMbps, downErr := masque.MeasureNativeDownloadReadMbps(downConn, tunRecycleDownloadDur)
	_ = downConn.Close()
	if downErr != nil && downBytes == 0 {
		t.Fatalf("download after server recycle: %v", downErr)
	}
	t.Logf("post-recycle native download: %.1f Mbit/s (%d bytes)", downMbps, downBytes)

	if downMbps < tunRecyclePreflightMin {
		t.Fatalf("download preflight dead: %.1f Mbit/s want >= %.1f (Docker connect-ip-h3-tun analog)",
			downMbps, tunRecyclePreflightMin)
	}
	minDown := masque.ConnectIPSynthRegressionFloorDownMbps()
	if downMbps < minDown {
		t.Fatalf("download after server recycle %.1f < regression floor %.1f Mbit/s",
			downMbps, minDown)
	}
}

// RunGATEConnectIPTunNativeH3PostUploadSameSessionControl verifies download works without server restart.
func RunGATEConnectIPTunNativeH3PostUploadSameSessionControl(t *testing.T) {
	t.Helper()
	uploadLn := masque.StartConnectIPNativeUploadSink(t)
	downLn := StartNativeConnectIPDownloadTarget(t)
	proxyPort := StartNativeConnectIPH3Server(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sess, err := (masque.CoreClientFactory{}).NewSession(ctx, NativeH3ClientOptions(proxyPort))
	if err != nil {
		t.Fatalf("new session: %v", err)
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
	_, upMbps, _ := masque.MeasureNativeUploadMbps(upConn, tunRecycleUploadDur)
	_ = upConn.Close()
	t.Logf("same-session upload: %.1f Mbit/s", upMbps)

	downPort := uint16(downLn.Addr().(*net.TCPAddr).Port)
	downConn, err := sess.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", downPort))
	if err != nil {
		t.Fatalf("dial download same session: %v", err)
	}
	masque.PrimeNativeTCPDownload(downConn)
	_, downMbps, err := masque.MeasureNativeDownloadReadMbps(downConn, tunRecycleDownloadDur)
	_ = downConn.Close()
	if err != nil {
		t.Logf("download ended: %v", err)
	}
	t.Logf("same-session download: %.1f Mbit/s", downMbps)
	if downMbps < masque.ConnectIPSynthRegressionFloorDownMbps() {
		t.Fatalf("same-session download %.1f < floor %.1f",
			downMbps, masque.ConnectIPSynthRegressionFloorDownMbps())
	}
}

// RunGATEConnectIPTunNativeH3PostUploadSameSessionProbeThenBulk mirrors Docker after upload:
// nc probe (short TCP) then iperf download (bulk TCP) on the same session without server restart.
func RunGATEConnectIPTunNativeH3PostUploadSameSessionProbeThenBulk(t *testing.T) {
	t.Helper()
	uploadLn := masque.StartConnectIPNativeUploadSink(t)
	downLn := StartNativeConnectIPDownloadTarget(t)
	proxyPort := StartNativeConnectIPH3Server(t)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	sess, err := (masque.CoreClientFactory{}).NewSession(ctx, NativeH3ClientOptions(proxyPort))
	if err != nil {
		t.Fatalf("new session: %v", err)
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
	upBytes, upMbps, err := masque.MeasureNativeUploadMbps(upConn, tunRecycleUploadDur)
	_ = upConn.Close()
	if err != nil && upBytes == 0 {
		t.Fatalf("upload: %v", err)
	}
	t.Logf("probe-then-bulk upload: %.1f Mbit/s (%d bytes)", upMbps, upBytes)
	masque.WaitNativeConnectIPEgressSettled(ctx, 2*time.Second)

	downPort := uint16(downLn.Addr().(*net.TCPAddr).Port)
	downAddr := M.ParseSocksaddrHostPort("127.0.0.1", downPort)

	probeConn, err := sess.DialContext(ctx, "tcp", downAddr)
	if err != nil {
		t.Fatalf("download TCP probe dial: %v", err)
	}
	if _, err := probeConn.Write([]byte{0x42}); err != nil {
		_ = probeConn.Close()
		t.Fatalf("download TCP probe write: %v", err)
	}
	_ = probeConn.Close()
	t.Log("download TCP probe OK (nc analog)")
	masque.WaitNativeConnectIPEgressSettled(ctx, 500*time.Millisecond)

	bulkConn, err := sess.DialContext(ctx, "tcp", downAddr)
	if err != nil {
		t.Fatalf("dial download bulk after probe: %v", err)
	}
	masque.PrimeNativeTCPDownload(bulkConn)
	downBytes, downMbps, err := masque.MeasureNativeDownloadReadMbps(bulkConn, tunRecycleDownloadDur)
	_ = bulkConn.Close()
	if err != nil && downBytes == 0 {
		t.Fatalf("download bulk after probe: %v", err)
	}
	t.Logf("download bulk after probe: %.1f Mbit/s (%d bytes)", downMbps, downBytes)
	if downMbps < tunRecyclePreflightMin {
		t.Fatalf("download bulk dead after probe: %.1f Mbit/s want >= %.1f (Docker nc OK / iperf dead analog)",
			downMbps, tunRecyclePreflightMin)
	}
	if downMbps < masque.ConnectIPSynthRegressionFloorDownMbps() {
		t.Fatalf("download bulk %.1f < regression floor %.1f",
			downMbps, masque.ConnectIPSynthRegressionFloorDownMbps())
	}
}

// RunGATEConnectIPTunNativeH3PostUploadServerRecycleSameSession upload → server restart →
// reuse session (no fresh CoreClientFactory) → download. Catches stale QUIC/IPConn reuse.
func RunGATEConnectIPTunNativeH3PostUploadServerRecycleSameSession(t *testing.T) {
	t.Helper()
	uploadLn := masque.StartConnectIPNativeUploadSink(t)
	downLn := StartNativeConnectIPDownloadTarget(t)
	srv := NewNativeConnectIPH3Server(t)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	sess, err := (masque.CoreClientFactory{}).NewSession(ctx, NativeH3ClientOptions(srv.Port()))
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
	upBytes, upMbps, _ := masque.MeasureNativeUploadMbps(upConn, tunRecycleUploadDur)
	_ = upConn.Close()
	t.Logf("same-session pre-recycle upload: %.1f Mbit/s (%d bytes)", upMbps, upBytes)
	masque.WaitNativeConnectIPEgressSettled(ctx, tunRecycleRacePause)

	_ = downLn.Close()
	downLn = StartNativeConnectIPDownloadTarget(t)
	srv.Restart(t)
	masque.InttestMarkConnectIPServerRecycled(sess)
	time.Sleep(tunRecycleRacePause)

	if _, err := sess.OpenIPSession(ctx); err != nil {
		t.Fatalf("OpenIPSession after server recycle: %v", err)
	}

	downPort := uint16(downLn.Addr().(*net.TCPAddr).Port)
	downAddr := M.ParseSocksaddrHostPort("127.0.0.1", downPort)
	probeConn, err := sess.DialContext(ctx, "tcp", downAddr)
	if err != nil {
		t.Fatalf("download probe after recycle same session: %v", err)
	}
	_ = probeConn.Close()

	downConn, err := sess.DialContext(ctx, "tcp", downAddr)
	if err != nil {
		t.Fatalf("dial download after recycle same session: %v", err)
	}
	masque.PrimeNativeTCPDownload(downConn)
	downBytes, downMbps, err := masque.MeasureNativeDownloadReadMbps(downConn, tunRecycleDownloadDur)
	_ = downConn.Close()
	if err != nil && downBytes == 0 {
		t.Fatalf("download after recycle same session: %v", err)
	}
	t.Logf("post-recycle same-session download: %.1f Mbit/s (%d bytes)", downMbps, downBytes)
	if downMbps < tunRecyclePreflightMin {
		t.Fatalf("download dead after server recycle (same session): %.1f Mbit/s want >= %.1f",
			downMbps, tunRecyclePreflightMin)
	}
}
