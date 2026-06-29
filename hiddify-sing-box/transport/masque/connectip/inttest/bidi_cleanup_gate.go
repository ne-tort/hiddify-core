package inttest

// LIFE-5: bidi cleanup after upload→download→close (native packet plane, CM relay).

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque"
	M "github.com/sagernet/sing/common/metadata"
)

const (
	bidiCleanupUploadDur   = lifecycleUploadProbeDur
	bidiCleanupDownloadDur = lifecycleDownloadProbeDur
	bidiCleanupSettlePause = 500 * time.Millisecond
	bidiCleanupMinBytes    = 32 * 1024
)

// RunGATEConnectIPBidiCleanupAfterUploadDownload proves upload→download→close leaves no relay
// or goroutine leaks on native H3 packet plane and CM netstack paths.
func RunGATEConnectIPBidiCleanupAfterUploadDownload(t *testing.T) {
	t.Helper()
	t.Run("NativeH3PacketPlane", runBidiCleanupNativeH3PacketPlane)
	t.Run("CMNetstackRelay", runBidiCleanupCMNetstackRelay)
}

func runBidiCleanupNativeH3PacketPlane(t *testing.T) {
	t.Helper()
	uploadLn := masque.StartConnectIPNativeUploadSink(t)
	downLn := StartNativeConnectIPDownloadTarget(t)
	srv := NewNativeConnectIPH3Server(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	beforeSess := goroutineCount()
	sess, err := (masque.CoreClientFactory{}).NewSession(ctx, NativeH3ClientOptions(srv.Port()))
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
	upBytes, _, upErr := masque.MeasureNativeUploadMbps(upConn, bidiCleanupUploadDur)
	_ = upConn.Close()
	if upErr != nil && upBytes == 0 {
		_ = sess.Close()
		t.Fatalf("upload: %v", upErr)
	}
	masque.WaitNativeConnectIPEgressSettled(ctx, bidiCleanupSettlePause)

	downPort := uint16(downLn.Addr().(*net.TCPAddr).Port)
	downConn, err := sess.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", downPort))
	if err != nil {
		_ = sess.Close()
		t.Fatalf("dial download: %v", err)
	}
	masque.PrimeNativeTCPDownload(downConn)
	downBytes, _, downErr := masque.MeasureNativeDownloadReadMbps(downConn, bidiCleanupDownloadDur)
	_ = downConn.Close()
	if downErr != nil && downBytes == 0 {
		_ = sess.Close()
		t.Fatalf("download: %v", downErr)
	}
	if downBytes < bidiCleanupMinBytes {
		_ = sess.Close()
		t.Fatalf("download after upload=%d bytes want >= %d", downBytes, bidiCleanupMinBytes)
	}
	masque.WaitNativeConnectIPEgressSettled(ctx, bidiCleanupSettlePause)

	_ = sess.Close()
	masque.WaitNativeConnectIPEgressSettled(ctx, tunRecycleRacePause)
	assertGoroutineDelta(t, beforeSess)
}

func runBidiCleanupCMNetstackRelay(t *testing.T) {
	t.Helper()
	uploadLn := masque.StartConnectIPNativeUploadSink(t)
	downLn := StartNativeConnectIPDownloadTarget(t)
	srv := NewNativeConnectIPH3Server(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	beforeSess := goroutineCount()
	sess, err := (masque.CoreClientFactory{}).NewSession(ctx, NativeH3ClientOptions(srv.Port()))
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	if _, err := sess.OpenIPSession(ctx); err != nil {
		_ = sess.Close()
		t.Fatalf("OpenIPSession: %v", err)
	}
	r := masque.NewConnectIPTunCMRouter(t, sess)

	upPort := uint16(uploadLn.Addr().(*net.TCPAddr).Port)
	upBytes := runConnectIPTunCMUpload(t, r, upPort, bidiCleanupUploadDur)
	if upBytes == 0 {
		_ = sess.Close()
		t.Fatal("CM upload produced no bytes")
	}
	if n := r.ActiveRelayCount(); n != 0 {
		_ = sess.Close()
		t.Fatalf("CM active relays after upload: %d want 0", n)
	}
	masque.WaitNativeConnectIPEgressSettled(ctx, bidiCleanupSettlePause)

	downPort := uint16(downLn.Addr().(*net.TCPAddr).Port)
	downBytes, _ := runConnectIPTunCMDownload(t, r, downPort, bidiCleanupDownloadDur)
	if downBytes < bidiCleanupMinBytes {
		_ = sess.Close()
		t.Fatalf("CM download after upload=%d bytes want >= %d", downBytes, bidiCleanupMinBytes)
	}
	if n := r.ActiveRelayCount(); n != 0 {
		_ = sess.Close()
		t.Fatalf("CM active relays after download: %d want 0", n)
	}
	masque.WaitNativeConnectIPEgressSettled(ctx, bidiCleanupSettlePause)

	_ = sess.Close()
	masque.WaitNativeConnectIPEgressSettled(ctx, tunRecycleRacePause)
	assertGoroutineDelta(t, beforeSess)
}
