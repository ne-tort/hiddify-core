package masque_test

// GATE-SESSION-DEATH: after heavy download + abrupt client abort, a dead shared QUIC client
// must not poison the H3 session (field: VPN stays "on", probes hang until explicit disconnect).

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque"
)

const (
	sessionDeathAbortCycles   = 8
	sessionDeathAbortHold     = 2500 * time.Millisecond
	sessionDeathPostProbeWait = 8 * time.Second
)

func runSocksDownloadWriteToAbruptAbort(t *testing.T, socksPort, targetPort uint16) {
	t.Helper()
	conn := masque.ExportSocksTCPDial(t, socksPort, targetPort)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if wt, ok := masque.ExportWriterTo(conn); ok {
			_, _ = wt.WriteTo(io.Discard)
			return
		}
		_, _ = io.Copy(io.Discard, conn)
	}()
	time.Sleep(sessionDeathAbortHold)
	_ = conn.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
}

func postChurnProbeSocksWithTimeout(t *testing.T, socksPort, targetPort uint16, wait time.Duration) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- runShortHTTPSocksOnce(socksPort, targetPort) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("post-death SOCKS probe (stale QUIC not recovered): %v", err)
		}
	case <-time.After(wait):
		t.Fatal("post-death SOCKS probe timed out (stale QUIC client poisoned session)")
	}
}

// TestGATEH3ConnectStreamBenchAbortStaleQUICPostProbe (GATE-SESSION-DEATH) — prod SOCKS/CM
// WriteTo bench aborted mid-flight, then shared QUIC client dies; post-probe must recover.
func TestGATEH3ConnectStreamBenchAbortStaleQUICPostProbe(t *testing.T) {
	targetPort := masque.ExportStartH2ProdStackBulkDownloadTarget(t)
	proxyPort := startLaunchMasqueStackH3ConnectStreamServer(t)
	session, ctx := masque.ExportNewConnectStreamH3ProdSessionWithTimeout(t, proxyPort, 3*time.Minute)
	socksPort := masque.ExportStartH3ConnectStreamSocksRouterWithSession(t, session)

	for i := 0; i < sessionDeathAbortCycles; i++ {
		runSocksDownloadWriteToAbruptAbort(t, socksPort, targetPort)
	}

	masque.ExportCloseConnectStreamH3CachedQUICForTest(t, session)
	time.Sleep(50 * time.Millisecond)

	probeCtx, cancel := context.WithTimeout(ctx, sessionDeathPostProbeWait)
	defer cancel()
	postChurnProbeDirect(t, session, probeCtx, targetPort)
	postChurnProbeSocksWithTimeout(t, socksPort, targetPort, sessionDeathPostProbeWait)
}

// TestGATEH3ConnectStreamSequentialBenchAbortBudgetProbe — sequential WriteTo downloads
// aborted mid-flight must not leak stream-budget / poison the shared QUIC session.
func TestGATEH3ConnectStreamSequentialBenchAbortBudgetProbe(t *testing.T) {
	targetPort := masque.ExportStartH2ProdStackBulkDownloadTarget(t)
	proxyPort := startLaunchMasqueStackH3ConnectStreamServer(t)
	session, ctx := masque.ExportNewConnectStreamH3ProdSessionWithTimeout(t, proxyPort, 3*time.Minute)
	socksPort := masque.ExportStartH3ConnectStreamSocksRouterWithSession(t, session)

	for i := 0; i < sessionDeathAbortCycles; i++ {
		runSocksDownloadWriteToAbruptAbort(t, socksPort, targetPort)
	}

	probeCtx, cancel := context.WithTimeout(ctx, sessionDeathPostProbeWait)
	defer cancel()
	postChurnProbeDirect(t, session, probeCtx, targetPort)
	postChurnProbeSocksWithTimeout(t, socksPort, targetPort, sessionDeathPostProbeWait)
}
