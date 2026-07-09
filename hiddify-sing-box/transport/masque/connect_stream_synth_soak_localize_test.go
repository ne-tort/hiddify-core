package masque_test

// GATE-SYNTH-CHURN: fast in-proc localization for CONNECT-stream QUIC slot recycle on Close
// without 90s timed soak or Docker stress. Replaces long soak in Verify-ConnectStream.ps1.

import (
	"context"
	"math"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque"
	M "github.com/sagernet/sing/common/metadata"
)

const (
	// synthChurnN — above typical peer bidi stream limit (~100); leaks surface before post-probe.
	synthChurnN              = 100
	synthChurnMinOKRate      = 0.95
	synthChurnPostProbeWait  = 10 * time.Second
	synthChurnReqTimeout     = 8 * time.Second
	synthChurnParallelTotal  = 80
	synthChurnParallelWorker = 8
)

func dialDirectOnce(ctx context.Context, session masque.ClientSession, dest M.Socksaddr) (net.Conn, error) {
	type result struct {
		conn net.Conn
		err  error
	}
	done := make(chan result, 1)
	go func() {
		conn, err := session.DialContext(ctx, "tcp", dest)
		done <- result{conn, err}
	}()
	select {
	case r := <-done:
		return r.conn, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func setupSynthChurnHarness(t *testing.T) (socksPort, targetPort uint16, session masque.ClientSession, ctx context.Context) {
	t.Helper()
	targetPort = startShortHTTPBurstTargetSimple(t)
	proxyPort := startLaunchMasqueStackH3ConnectStreamServer(t)
	session, ctx = masque.ExportNewConnectStreamH3ProdSessionWithTimeout(t, proxyPort, 3*time.Minute)
	socksPort = masque.ExportStartH3ConnectStreamSocksRouterWithSession(t, session)
	return socksPort, targetPort, session, ctx
}

func postChurnProbeDirect(t *testing.T, session masque.ClientSession, ctx context.Context, targetPort uint16) {
	t.Helper()
	probeCtx, cancel := context.WithTimeout(ctx, synthChurnPostProbeWait)
	defer cancel()
	conn, err := session.DialContext(probeCtx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", targetPort))
	if err != nil {
		t.Fatalf("post-churn direct dial (session poisoned): %v", err)
	}
	_ = conn.Close()
}

func postChurnProbeSocks(t *testing.T, socksPort, targetPort uint16) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- runShortHTTPSocksOnce(socksPort, targetPort) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("post-churn SOCKS request (session poisoned): %v", err)
		}
	case <-time.After(synthChurnPostProbeWait):
		t.Fatal("post-churn SOCKS request timed out (session poisoned)")
	}
}

// TestGATEH3ConnectStreamDirectSessionChurnNoPoison (GATE-SYNTH-DIRECT) — sequential dial+close on one
// H3 session (no SOCKS/CM). Localizes QUIC stream-slot / request-context cancel leaks in MASQUE dial path.
func TestGATEH3ConnectStreamDirectSessionChurnNoPoison(t *testing.T) {
	_, targetPort, session, ctx := setupSynthChurnHarness(t)
	dest := M.ParseSocksaddrHostPort("127.0.0.1", targetPort)

	var ok, fail int
	firstFail := -1
	for i := 0; i < synthChurnN; i++ {
		reqCtx, cancel := context.WithTimeout(ctx, synthChurnReqTimeout)
		conn, err := dialDirectOnce(reqCtx, session, dest)
		cancel()
		if err != nil {
			fail++
			if firstFail < 0 {
				firstFail = i
				t.Logf("GATE-SYNTH-DIRECT first error @%d: %v", i, err)
			}
		} else {
			_ = conn.Close()
			ok++
		}
	}
	okRate := float64(ok) / float64(ok+fail)
	t.Logf("GATE-SYNTH-DIRECT: ok=%d fail=%d rate=%.1f%% first_fail=%d", ok, fail, okRate*100, firstFail)
	minOK := int(math.Floor(float64(synthChurnN) * synthChurnMinOKRate))
	if ok < minOK {
		t.Fatalf("GATE-SYNTH-DIRECT: ok=%d/%d (%.1f%%) want >= %.0f%%; first_fail@%d",
			ok, synthChurnN, okRate*100, synthChurnMinOKRate*100, firstFail)
	}
	postChurnProbeDirect(t, session, ctx, targetPort)
}

// TestGATEH3ConnectStreamDirectChurn90SubMaxStreams (GATE-SYNTH-MAXSTREAMS-90) — below QUIC
// DefaultMaxIncomingStreams (100): post-probe must PASS when Close recycles slots.
func TestGATEH3ConnectStreamDirectChurn90SubMaxStreams(t *testing.T) {
	_, targetPort, session, ctx := setupSynthChurnHarness(t)
	dest := M.ParseSocksaddrHostPort("127.0.0.1", targetPort)
	const n = 90
	for i := 0; i < n; i++ {
		reqCtx, cancel := context.WithTimeout(ctx, synthChurnReqTimeout)
		conn, err := dialDirectOnce(reqCtx, session, dest)
		cancel()
		if err != nil {
			t.Fatalf("GATE-SYNTH-MAXSTREAMS-90 dial@%d: %v", i, err)
		}
		_ = conn.Close()
	}
	postChurnProbeDirect(t, session, ctx, targetPort)
}

// TestGATEH3ConnectStreamSocksCMSequentialChurnNoPoison (GATE-SYNTH-SOCKS-SEQ) — sequential short HTTP
// through prod SOCKS + CM on one session. Localizes CM watchdog / CLOSE_WAIT interaction.
func TestGATEH3ConnectStreamSocksCMSequentialChurnNoPoison(t *testing.T) {
	socksPort, targetPort, _, ctx := setupSynthChurnHarness(t)

	var ok, fail int
	firstFail := -1
	for i := 0; i < synthChurnN; i++ {
		reqCtx, cancel := context.WithTimeout(ctx, synthChurnReqTimeout)
		done := make(chan error, 1)
		go func() { done <- runShortHTTPSocksOnce(socksPort, targetPort) }()
		var err error
		select {
		case err = <-done:
		case <-reqCtx.Done():
			err = reqCtx.Err()
		}
		cancel()
		if err != nil {
			fail++
			if firstFail < 0 {
				firstFail = i
			}
		} else {
			ok++
		}
	}
	okRate := float64(ok) / float64(ok+fail)
	t.Logf("GATE-SYNTH-SOCKS-SEQ: ok=%d fail=%d rate=%.1f%% first_fail=%d", ok, fail, okRate*100, firstFail)
	minOK := int(math.Floor(float64(synthChurnN) * synthChurnMinOKRate))
	if ok < minOK {
		t.Fatalf("GATE-SYNTH-SOCKS-SEQ: ok=%d/%d (%.1f%%) want >= %.0f%%; first_fail@%d",
			ok, synthChurnN, okRate*100, synthChurnMinOKRate*100, firstFail)
	}
	postChurnProbeSocks(t, socksPort, targetPort)
}

// TestGATEH3ConnectStreamSocksCMParallelChurnNoPoison (GATE-SYNTH-SOCKS-PAR) — parallel burst churn
// (same session, SOCKS/CM). Faster fan-out repro without timed soak.
func TestGATEH3ConnectStreamSocksCMParallelChurnNoPoison(t *testing.T) {
	socksPort, targetPort, _, ctx := setupSynthChurnHarness(t)
	ok, fail := runBurstGateParallel(t, socksPort, targetPort, ctx, synthChurnParallelWorker, synthChurnParallelTotal)
	total := ok + fail
	okRate := float64(ok) / float64(total)
	t.Logf("GATE-SYNTH-SOCKS-PAR: ok=%d fail=%d rate=%.1f%%", ok, fail, okRate*100)
	minOK := int(math.Floor(float64(synthChurnParallelTotal) * synthChurnMinOKRate))
	if ok < minOK {
		t.Fatalf("GATE-SYNTH-SOCKS-PAR: ok=%d/%d (%.1f%%) want >= %.0f%% (%d ok)",
			ok, total, okRate*100, synthChurnMinOKRate*100, minOK)
	}
	postChurnProbeSocks(t, socksPort, targetPort)
}

// TestGATEH3ConnectStreamSynthChurnDeathWindow (GATE-SYNTH-WINDOW) — diagnostic: first_fail index band.
func TestGATEH3ConnectStreamSynthChurnDeathWindow(t *testing.T) {
	if testing.Short() {
		t.Skip("diagnostic only")
	}
	_, targetPort, session, ctx := setupSynthChurnHarness(t)
	dest := M.ParseSocksaddrHostPort("127.0.0.1", targetPort)
	const n = 120
	var lastOK, firstFail = -1, -1
	for i := 0; i < n; i++ {
		reqCtx, cancel := context.WithTimeout(ctx, synthChurnReqTimeout)
		conn, err := dialDirectOnce(reqCtx, session, dest)
		cancel()
		if err != nil {
			if firstFail < 0 {
				firstFail = i
				t.Logf("GATE-SYNTH-WINDOW first_fail @%d: %v", i, err)
			}
		} else {
			_ = conn.Close()
			lastOK = i
		}
	}
	t.Logf("GATE-SYNTH-WINDOW direct: last_ok=%d first_fail=%d (n=%d)", lastOK, firstFail, n)
	probeCtx, probeCancel := context.WithTimeout(ctx, synthChurnPostProbeWait)
	defer probeCancel()
	_, probeErr := session.DialContext(probeCtx, "tcp", dest)
	if probeErr != nil {
		t.Logf("GATE-SYNTH-WINDOW post-churn probe FAIL: %v", probeErr)
	} else {
		t.Log("GATE-SYNTH-WINDOW post-churn probe PASS")
	}
	if firstFail >= 0 && firstFail < 110 {
		t.Log("hint: failure before peer MAX_STREAMS ~100 → QUIC stream slot leak on Close")
	}
	if firstFail >= 110 {
		t.Log("hint: failure after ~100 → cumulative stall, not raw dial leak")
	}
	if firstFail < 0 && probeErr != nil {
		t.Log("hint: all dials OK but post-probe FAIL → session poisoned at budget ceiling (~100 ghost streams)")
	}
}
