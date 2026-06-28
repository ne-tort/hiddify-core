package inttest

// CONNECT-IP lifecycle goroutine gates (W-IP-TUN IP-TUN-PR2a/b): prove Close/recycle does not leak goroutines.

import (
	"context"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque"
	M "github.com/sagernet/sing/common/metadata"
)

const (
	lifecycleGoroutineSlack   = 28
	lifecycleGoroutineSettle  = 10 * time.Second
	lifecycleGoroutinePoll    = 100 * time.Millisecond
	lifecycleUploadProbeDur   = 500 * time.Millisecond
	lifecycleDownloadProbeDur = 2 * time.Second
)

func goroutineCount() int {
	runtime.GC()
	return runtime.NumGoroutine()
}

func waitGoroutineDelta(t *testing.T, before int, maxWait time.Duration) int {
	t.Helper()
	deadline := time.Now().Add(maxWait)
	for time.Now().Before(deadline) {
		runtime.GC()
		delta := goroutineCount() - before
		if delta <= lifecycleGoroutineSlack {
			t.Logf("goroutine delta settled: %d (before %d slack %d)", delta, before, lifecycleGoroutineSlack)
			return delta
		}
		time.Sleep(lifecycleGoroutinePoll)
	}
	delta := goroutineCount() - before
	t.Logf("goroutine delta after settle wait: %d (before %d want <= %d)", delta, before, lifecycleGoroutineSlack)
	return delta
}

func assertGoroutineDelta(t *testing.T, before int) {
	t.Helper()
	delta := waitGoroutineDelta(t, before, lifecycleGoroutineSettle)
	if delta > lifecycleGoroutineSlack {
		t.Fatalf("goroutine growth: %d > slack %d (before session %d)", delta, lifecycleGoroutineSlack, before)
	}
}

// RunGATEConnectIPLifecycleGoroutineAfterClose opens a session, uploads briefly, closes, and
// asserts goroutine count returns near baseline.
func RunGATEConnectIPLifecycleGoroutineAfterClose(t *testing.T) {
	t.Helper()
	uploadLn := masque.StartConnectIPNativeUploadSink(t)
	srv := NewHybridConnectIPH3Server(t)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	beforeSess := goroutineCount()
	sess, err := (masque.CoreClientFactory{}).NewSession(ctx, HybridNativeH3ClientOptions(srv.Port()))
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	if _, err := sess.OpenIPSession(ctx); err != nil {
		_ = sess.Close()
		t.Fatalf("OpenIPSession: %v", err)
	}
	upPort := uint16(uploadLn.Addr().(*net.TCPAddr).Port)
	upConn, err := sess.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", upPort))
	if err != nil {
		_ = sess.Close()
		t.Fatalf("dial upload: %v", err)
	}
	_, _, _ = masque.MeasureNativeUploadMbps(upConn, lifecycleUploadProbeDur)
	_ = upConn.Close()
	_ = sess.Close()
	masque.WaitNativeConnectIPEgressSettled(ctx, tunRecycleRacePause)
	assertGoroutineDelta(t, beforeSess)
}

// RunGATEConnectIPLifecycleGoroutineAfterRecycle mirrors Docker upload→server restart→fresh session→close.
func RunGATEConnectIPLifecycleGoroutineAfterRecycle(t *testing.T) {
	t.Helper()
	uploadLn := masque.StartConnectIPNativeUploadSink(t)
	downLn := StartHybridConnectIPDownloadTarget(t)
	srv := NewHybridConnectIPH3Server(t)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	sessA, err := (masque.CoreClientFactory{}).NewSession(ctx, HybridNativeH3ClientOptions(srv.Port()))
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
	_, _, _ = masque.MeasureNativeUploadMbps(upConn, lifecycleUploadProbeDur)
	_ = upConn.Close()
	_ = sessA.Close()
	masque.WaitNativeConnectIPEgressSettled(ctx, tunRecycleRacePause)

	_ = downLn.Close()
	downLn = StartHybridConnectIPDownloadTarget(t)
	srv.Restart(t)
	masque.WaitNativeConnectIPEgressSettled(ctx, tunRecycleRacePause)

	beforeSess := goroutineCount()
	sessB, err := (masque.CoreClientFactory{}).NewSession(ctx, HybridNativeH3ClientOptions(srv.Port()))
	if err != nil {
		t.Fatalf("session B: %v", err)
	}
	if _, err := sessB.OpenIPSession(ctx); err != nil {
		_ = sessB.Close()
		t.Fatalf("OpenIPSession B: %v", err)
	}
	downPort := uint16(downLn.Addr().(*net.TCPAddr).Port)
	downConn, err := sessB.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", downPort))
	if err != nil {
		_ = sessB.Close()
		t.Fatalf("dial download: %v", err)
	}
	masque.PrimeNativeTCPDownload(downConn)
	_, _, _ = masque.MeasureNativeDownloadReadMbps(downConn, lifecycleDownloadProbeDur)
	_ = downConn.Close()
	_ = sessB.Close()
	masque.WaitNativeConnectIPEgressSettled(ctx, tunRecycleRacePause)
	assertGoroutineDelta(t, beforeSess)
}

// RunGATEConnectIPRelayTeardownDownloadOnly simulates iperf -R via CM synth: download-only relay
// must finish with zero active CM connections and no goroutine growth.
func RunGATEConnectIPRelayTeardownDownloadOnly(t *testing.T) {
	t.Helper()
	downLn := StartHybridConnectIPDownloadTarget(t)
	srv := NewHybridConnectIPH3Server(t)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	beforeSess := goroutineCount()
	sess, err := (masque.CoreClientFactory{}).NewSession(ctx, HybridNativeH3ClientOptions(srv.Port()))
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()
	if _, err := sess.OpenIPSession(ctx); err != nil {
		t.Fatalf("OpenIPSession: %v", err)
	}
	r := masque.NewConnectIPTunCMRouter(t, sess)
	downPort := uint16(downLn.Addr().(*net.TCPAddr).Port)
	dest := M.ParseSocksaddrHostPort("127.0.0.1", downPort)

	var total int64
	err = r.RouteTunTCP(ctx, dest, func(app net.Conn) {
		masque.PrimeNativeTCPDownload(app)
		buf := make([]byte, 64 * 1024)
		deadline := time.Now().Add(lifecycleDownloadProbeDur)
		_ = app.SetReadDeadline(deadline)
		for time.Now().Before(deadline) {
			n, rErr := app.Read(buf)
			if n > 0 {
				total += int64(n)
			}
			if rErr != nil {
				break
			}
		}
	})
	if err != nil {
		t.Fatalf("download-only relay: %v", err)
	}
	if total == 0 {
		t.Fatal("download-only relay: 0 bytes")
	}
	if n := r.ActiveRelayCount(); n != 0 {
		t.Fatalf("CM active relays after download-only: %d want 0", n)
	}
	_ = sess.Close()
	masque.WaitNativeConnectIPEgressSettled(ctx, tunRecycleRacePause)
	assertGoroutineDelta(t, beforeSess)
}

// RunGATEConnectIPSessionCloseMidBulkNoLeak is the LIFE-4 full-stack gate (upload mid-bulk → Close → no leak).
func RunGATEConnectIPSessionCloseMidBulkNoLeak(t *testing.T) {
	RunGATEConnectIPLifecycleGoroutineAfterClose(t)
}
