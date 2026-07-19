//go:build masque_inttest_heavy

package inttest

// P2-12 / F3-T5: sequential TCP connect/close churn on one CONNECT-IP plane
// (not parallel short storm — that is P1-4 MultiShort). Sticky bulk must survive;
// recycle latch stays false; post-churn dial works.

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque"
	M "github.com/sagernet/sing/common/metadata"
)

const (
	tcpChurnCycles       = 12
	tcpChurnTimeout      = 60 * time.Second
	tcpChurnDownloadDur  = 4 * time.Second
	tcpChurnWarmMin      = 8 * 1024
	tcpChurnFinalMin     = 32 * 1024
	tcpChurnAcceptWait   = 8 * time.Second
	tcpChurnMidCheckEvery = 4
)

// RunGATEConnectIPTCPConnectCloseChurn is P2-12 / F3-T5 (H3):
// one sticky bulk download + sequential dial/write/close cycles on the same plane.
func RunGATEConnectIPTCPConnectCloseChurn(t *testing.T) {
	t.Helper()
	runTCPConnectCloseChurn(t, "h3", StartNativeConnectIPH3Server, NativeH3ClientOptions)
}

// RunGATEConnectIPTCPConnectCloseChurnH2 is P2-12 H2 smoke of the same sequential churn.
func RunGATEConnectIPTCPConnectCloseChurnH2(t *testing.T) {
	t.Helper()
	runTCPConnectCloseChurn(t, "h2", StartNativeConnectIPH2Server, NativeH2ClientOptions)
}

func runTCPConnectCloseChurn(
	t *testing.T,
	layer string,
	startServer func(testing.TB) int,
	clientOpts func(int) masque.ClientOptions,
) {
	t.Helper()
	shortTarget, shortPort := startMultiShortEchoTarget(t)
	bulkLn := StartNativeConnectIPDownloadTarget(t)
	proxyPort := startServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), tcpChurnTimeout)
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
		deadline := time.Now().Add(tcpChurnDownloadDur)
		_ = bulkConn.SetReadDeadline(deadline)
		for time.Now().Before(deadline) {
			n, err := bulkConn.Read(buf)
			if n > 0 {
				bulkTotal.Add(int64(n))
			}
			if err != nil {
				return
			}
		}
	}()

	warmDeadline := time.Now().Add(2 * time.Second)
	for bulkTotal.Load() < tcpChurnWarmMin && time.Now().Before(warmDeadline) {
		time.Sleep(10 * time.Millisecond)
	}
	warmBytes := bulkTotal.Load()
	if warmBytes < tcpChurnWarmMin {
		t.Fatalf("bulk not live before TCP churn: %d bytes want >= %d", warmBytes, tcpChurnWarmMin)
	}
	assertNoRecycleLatch(t, sess, "before TCP churn")

	for i := 0; i < tcpChurnCycles; i++ {
		c, derr := sess.DialContext(ctx, "tcp", shortAddr)
		if derr != nil {
			t.Fatalf("churn dial %d: %v (server_accepted=%d)", i, derr, shortTarget.accepted.Load())
		}
		_ = c.SetDeadline(time.Now().Add(tcpChurnAcceptWait))
		if _, werr := c.Write([]byte{'s'}); werr != nil {
			_ = c.Close()
			t.Fatalf("churn write %d: %v", i, werr)
		}
		one := make([]byte, 1)
		if _, rerr := io.ReadFull(c, one); rerr != nil {
			_ = c.Close()
			t.Fatalf("churn read %d: %v", i, rerr)
		}
		if one[0] != 'k' {
			_ = c.Close()
			t.Fatalf("churn echo %d: got %q want 'k'", i, one)
		}
		if cerr := c.Close(); cerr != nil {
			t.Fatalf("churn close %d: %v", i, cerr)
		}
		if (i+1)%tcpChurnMidCheckEvery == 0 {
			assertNoRecycleLatch(t, sess, "mid churn")
			if bulkTotal.Load() <= warmBytes {
				t.Fatalf("bulk stalled during sequential churn at cycle %d: warm=%d now=%d",
					i, warmBytes, bulkTotal.Load())
			}
		}
	}
	afterChurnBytes := bulkTotal.Load()
	assertNoRecycleLatch(t, sess, "after TCP churn")
	if afterChurnBytes <= warmBytes {
		t.Fatalf("bulk stalled across full churn: warm=%d after=%d", warmBytes, afterChurnBytes)
	}
	if shortTarget.accepted.Load() < uint64(tcpChurnCycles) {
		t.Fatalf("echo accepted %d want >= %d", shortTarget.accepted.Load(), tcpChurnCycles)
	}

	<-bulkDone
	finalBytes := bulkTotal.Load()
	assertNoRecycleLatch(t, sess, "after bulk window")
	t.Logf("tcp-churn layer=%s: cycles=%d warm=%d after_churn=%d final=%d latch=false",
		layer, tcpChurnCycles, warmBytes, afterChurnBytes, finalBytes)
	if finalBytes < tcpChurnFinalMin {
		t.Fatalf("bulk too small after churn: %d bytes want >= %d", finalBytes, tcpChurnFinalMin)
	}

	c, err := sess.DialContext(ctx, "tcp", shortAddr)
	if err != nil {
		t.Fatalf("post-churn short dial: %v", err)
	}
	_ = c.SetDeadline(time.Now().Add(tcpChurnAcceptWait))
	if _, err := c.Write([]byte{'s'}); err != nil {
		_ = c.Close()
		t.Fatalf("post-churn write: %v", err)
	}
	one := make([]byte, 1)
	if _, err := io.ReadFull(c, one); err != nil {
		_ = c.Close()
		t.Fatalf("post-churn read: %v", err)
	}
	_ = c.Close()
	assertNoRecycleLatch(t, sess, "after post-churn short")
}
