//go:build masque_inttest_heavy

package inttest

// P3-4 / F3-T2: sticky TCP bulk + benign plane half-close (0x100 / EOF / ErrClosed)
// must not set recycle latch; siblings / post-dial survive.

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/sagernet/sing-box/transport/masque"
	M "github.com/sagernet/sing/common/metadata"
)

const (
	benignHalfCloseTimeout     = 60 * time.Second
	benignHalfCloseDownloadDur = 3 * time.Second
	benignHalfCloseWarmMin     = 8 * 1024
	benignHalfCloseFinalMin    = 32 * 1024
	benignHalfCloseAcceptWait  = 8 * time.Second
)

// RunGATEConnectIPBenignHalfCloseMultiFlow is P3-4 / F3-T2 (H3).
func RunGATEConnectIPBenignHalfCloseMultiFlow(t *testing.T) {
	t.Helper()
	runBenignHalfCloseMultiFlow(t, "h3", StartNativeConnectIPH3Server, NativeH3ClientOptions)
}

// RunGATEConnectIPBenignHalfCloseMultiFlowH2 is P3-4 H2 smoke.
func RunGATEConnectIPBenignHalfCloseMultiFlowH2(t *testing.T) {
	t.Helper()
	runBenignHalfCloseMultiFlow(t, "h2", StartNativeConnectIPH2Server, NativeH2ClientOptions)
}

func runBenignHalfCloseMultiFlow(
	t *testing.T,
	layer string,
	startServer func(testing.TB) int,
	clientOpts func(int) masque.ClientOptions,
) {
	t.Helper()
	shortTarget, shortPort := startMultiShortEchoTarget(t)
	bulkLn := StartNativeConnectIPDownloadTarget(t)
	proxyPort := startServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), benignHalfCloseTimeout)
	defer cancel()

	sess, err := (masque.CoreClientFactory{}).NewSession(ctx, clientOpts(proxyPort))
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()
	if _, err := sess.OpenIPSession(ctx); err != nil {
		t.Fatalf("OpenIPSession: %v", err)
	}
	assertNoRecycleLatch(t, sess, "after OpenIPSession")

	shortAddr := M.ParseSocksaddrHostPort("127.0.0.1", shortPort)
	bulkAddr := M.ParseSocksaddrHostPort("127.0.0.1", uint16(bulkLn.Addr().(*net.TCPAddr).Port))

	bulkConn, err := sess.DialContext(ctx, "tcp", bulkAddr)
	if err != nil {
		t.Fatalf("bulk dial: %v", err)
	}
	masque.PrimeNativeTCPDownload(bulkConn)

	var bulkTotal atomic.Int64
	bulkDone := make(chan struct{})
	go func() {
		defer close(bulkDone)
		defer bulkConn.Close()
		buf := make([]byte, 64*1024)
		deadline := time.Now().Add(benignHalfCloseDownloadDur)
		_ = bulkConn.SetReadDeadline(deadline)
		for time.Now().Before(deadline) {
			n, rerr := bulkConn.Read(buf)
			if n > 0 {
				bulkTotal.Add(int64(n))
			}
			if rerr != nil {
				return
			}
		}
	}()

	warmDeadline := time.Now().Add(2 * time.Second)
	for bulkTotal.Load() < benignHalfCloseWarmMin && time.Now().Before(warmDeadline) {
		time.Sleep(10 * time.Millisecond)
	}
	warmBytes := bulkTotal.Load()
	if warmBytes < benignHalfCloseWarmMin {
		t.Fatalf("bulk not live before benign half-close: %d want >= %d", warmBytes, benignHalfCloseWarmMin)
	}
	assertNoRecycleLatch(t, sess, "before benign half-close")

	benign := []struct {
		name string
		err  error
	}{
		{"h3_0x100", &quic.ApplicationError{ErrorCode: 0x100, Remote: true}},
		{"eof", io.EOF},
		{"err_closed", net.ErrClosed},
	}
	for _, tc := range benign {
		masque.InttestNoteConnectIPPlaneFatal(sess, tc.err)
		if masque.InttestConnectIPServerGenerationStale(sess) {
			t.Fatalf("recycle latch set after benign %s (F3-T2)", tc.name)
		}
	}
	// Non-benign control: must latch, then clear for restore checks.
	masque.InttestNoteConnectIPPlaneFatal(sess, &quic.ApplicationError{ErrorCode: 0x101, Remote: true})
	if !masque.InttestConnectIPServerGenerationStale(sess) {
		t.Fatal("expected latch after remote app error 0x101")
	}
	masque.InttestClearConnectIPServerRecycled(sess)
	assertNoRecycleLatch(t, sess, "after clear post-control-fatal")

	<-bulkDone
	finalBytes := bulkTotal.Load()
	t.Logf("benign-halfclose layer=%s: warm=%d final=%d latch=false", layer, warmBytes, finalBytes)
	if finalBytes < benignHalfCloseFinalMin {
		t.Fatalf("bulk too small: %d want >= %d", finalBytes, benignHalfCloseFinalMin)
	}

	c, err := sess.DialContext(ctx, "tcp", shortAddr)
	if err != nil {
		t.Fatalf("post-benign TCP dial: %v", err)
	}
	_ = c.SetDeadline(time.Now().Add(benignHalfCloseAcceptWait))
	if _, err := c.Write([]byte{'s'}); err != nil {
		_ = c.Close()
		t.Fatalf("post-benign write: %v", err)
	}
	one := make([]byte, 1)
	if _, err := io.ReadFull(c, one); err != nil {
		_ = c.Close()
		t.Fatalf("post-benign read: %v", err)
	}
	_ = c.Close()
	if shortTarget.accepted.Load() < 1 {
		t.Fatal("post-benign echo never accepted")
	}
	assertNoRecycleLatch(t, sess, "after post-benign dial")
}
