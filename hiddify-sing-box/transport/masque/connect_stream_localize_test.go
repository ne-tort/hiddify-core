package masque

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing-box/transport/masque/h3"
	strm "github.com/sagernet/sing-box/transport/masque/stream"
)

// connectStreamLocalize bands (Mbit/s) for in-process CONNECT-stream benches.
const (
	connectStreamLocalizeFastMbps            = 80.0
	connectStreamLocalizeUploadWindowedMin   = 4.0  // upload on 64 KiB/35 ms wire-FC band
	connectStreamLocalizeUploadWindowedMax   = 28.0
	connectStreamLocalizeDownloadKPIMin      = 21.0 // K-S1/K-S2 floor (eager WINDOW default on download)
	connectStreamLocalizeWideUploadMinMbps   = 40.0 // L2 16 MiB window upload escapes L3 wire-FC (~15)
	connectStreamLocalizeInstantUploadMinMbps = 40.0 // L1 instant upload on MASQUE bidi (not raw TCP 80)
	// Legacy aliases — upload wire-FC band (arch/investigation tests).
	connectStreamLocalizeCeilingMin          = connectStreamLocalizeUploadWindowedMin
	connectStreamLocalizeCeilingMax          = connectStreamLocalizeUploadWindowedMax
)

type connectStreamBenchResult struct {
	layer string
	mbps  float64
	bytes int64
	err   error
}

func assertConnectStreamWindowedCeilingBand(t *testing.T, mbps float64, context string) {
	t.Helper()
	if mbps <= connectStreamVPSKPITargetDownMbps {
		t.Fatalf("%s: %.1f Mbit/s (want > %.0f)", context, mbps, connectStreamVPSKPITargetDownMbps)
	}
}

func (r connectStreamBenchResult) ok() bool { return r.err == nil }

// bidiLink models the HTTP/3 CONNECT-stream bidi byte pipe for localize benches.
type bidiLink interface {
	wrap(net.Conn) net.Conn
}

type instantBidiLink struct{}

func (instantBidiLink) wrap(c net.Conn) net.Conn { return c }

// readAsWriterTo adapts Read-path TCP for WriteTo bench parity on L0.
type readAsWriterTo struct{ net.Conn }

func (c readAsWriterTo) WriteTo(w io.Writer) (int64, error) { return io.Copy(w, c.Conn) }

// benchConnWriteTo adapts Read-path TCP for WriteTo bench with prod-sized copy buffer (256 KiB).
type benchConnWriteTo struct{ net.Conn }

func (c benchConnWriteTo) WriteTo(w io.Writer) (int64, error) {
	buf := make([]byte, 256*1024)
	return io.CopyBuffer(w, c.Conn, buf)
}

// windowedBidiLink limits per-direction in-flight bytes (Write=C2S, Read=S2C) and returns
// credit after RTT (bench-shaped ~64 KiB / RTT ≈ 13–15 Mbit/s at 35 ms).
type windowedBidiLink struct {
	rtt              time.Duration
	windowBytes      int
	noLimitS2C       bool // B2 bypass: unlimited download (response) credit
	instantCredit    bool // B7 bypass: ACK/credit without RTT delay (both directions)
	instantCreditS2C bool // prod eager WINDOW_UPDATE: instant download credit only
}

func (w windowedBidiLink) wrap(inner net.Conn) net.Conn {
	return h3.WrapBidiWindow(inner, h3.BidiWindowConfig{
		RTT:              w.rtt,
		WindowBytes:      w.windowBytes,
		NoLimitS2C:       w.noLimitS2C,
		InstantCredit:    w.instantCredit,
		InstantCreditS2C: w.instantCreditS2C,
	})
}

func bypassB2BidiLink() windowedBidiLink {
	return windowedBidiLink{
		rtt:         localizeBenchRTT,
		windowBytes: localizeBenchWindowBytes,
		noLimitS2C:  true,
	}
}

func bypassB7BidiLink() windowedBidiLink {
	return windowedBidiLink{
		rtt:           localizeBenchRTT,
		windowBytes:   localizeBenchWindowBytes,
		instantCredit: true,
	}
}

func bypassB8BidiLink() windowedBidiLink {
	return windowedBidiLink{
		rtt:         40 * time.Millisecond,
		windowBytes: localizeBenchWindowBytes,
	}
}

type connectStreamHarness struct {
	conn     net.Conn
	session  ClientSession
	targetLn net.Listener
	closeFn  func()
}

// connectStreamHarnessOpts configures in-process CONNECT-stream harness probes (S41, S89).
type connectStreamHarnessOpts struct {
	BidiWakeSink h3.BidiWakeSink
	PipeUpload   bool // MASQUE_CONNECT_STREAM_PIPE_UPLOAD=1 (legacy pipe upload body)
	DualConnect  bool // MASQUE_CONNECT_STREAM_DUAL_CONNECT=1 (P2 dual-leg sketch)
	Thin         bool // MASQUE_CONNECT_STREAM_THIN=1 (Invisv HTTPStreamer path, REF3-4)
}

func applyConnectStreamHarnessEnv(tb testing.TB, o connectStreamHarnessOpts) {
	tb.Helper()
	if o.Thin {
		tb.Setenv("MASQUE_CONNECT_STREAM_THIN", "1")
		tb.Setenv("MASQUE_CONNECT_STREAM_DUAL_CONNECT", "0")
		tb.Setenv("MASQUE_CONNECT_STREAM_PIPE_UPLOAD", "0")
		tb.Setenv("MASQUE_H3_BIDI_DUPLEX_COORD", "0")
		return
	}
	if o.DualConnect {
		tb.Setenv("MASQUE_CONNECT_STREAM_DUAL_CONNECT", "1")
		return
	}
	tb.Setenv("MASQUE_CONNECT_STREAM_DUAL_CONNECT", "0")
	if o.PipeUpload {
		tb.Setenv("MASQUE_CONNECT_STREAM_PIPE_UPLOAD", "1")
	} else {
		tb.Setenv("MASQUE_CONNECT_STREAM_PIPE_UPLOAD", "0")
	}
}

// unwrapDualTunnelConn walks masque wrappers to *h3.DualTunnelConn.
func unwrapDualTunnelConn(conn net.Conn) (*h3.DualTunnelConn, bool) {
	for conn != nil {
		if dc, ok := conn.(*h3.DualTunnelConn); ok {
			return dc, true
		}
		switch c := conn.(type) {
		case *strm.TunnelConn:
			conn = c.Inner
		default:
			if inner, ok := h3.BidiWindowInner(conn); ok {
				conn = inner
			} else {
				return nil, false
			}
		}
	}
	return nil, false
}

func wrapConnectStreamHarnessConn(link bidiLink, conn net.Conn) net.Conn {
	if dc, ok := unwrapDualTunnelConn(conn); ok {
		return strm.NewTunnelConn(h3.NewDualTunnelConn(h3.DualTunnelConnParams{
			Download: link.wrap(dc.DownloadLeg()),
			Upload:   link.wrap(dc.UploadLeg()),
		}))
	}
	return link.wrap(conn)
}

func applyConnectStreamTunnelHook(o connectStreamHarnessOpts) func() {
	prev := h3.TunnelConnParamsHook
	if o.BidiWakeSink != nil {
		sink := o.BidiWakeSink
		h3.TunnelConnParamsHook = func(p *h3.TunnelConnParams) {
			p.BidiWakeSink = sink
		}
	}
	return func() {
		h3.TunnelConnParamsHook = prev
	}
}

func (h *connectStreamHarness) close() {
	if h.conn != nil {
		_ = h.conn.Close()
	}
	if h.closeFn != nil {
		h.closeFn()
	}
}

func startConnectStreamUploadHarness(tb testing.TB, link bidiLink, opts ...connectStreamHarnessOpts) *connectStreamHarness {
	tb.Helper()
	var o connectStreamHarnessOpts
	if len(opts) > 0 {
		o = opts[0]
	}
	applyConnectStreamHarnessEnv(tb, o)
	cleanupHook := applyConnectStreamTunnelHook(o)
	tb.Cleanup(cleanupHook)
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("remote listen: %v", err)
	}
	go func() {
		for {
			c, err := targetLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(io.Discard, c)
			}(c)
		}
	}()

	proxyPort := startInProcessTCPConnectProxy(tb, connectStreamRelayHandler)
	waitCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	tb.Cleanup(cancel)

	session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
		Server:              "127.0.0.1",
		ServerPort:          uint16(proxyPort),
		MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
		TCPTransport:        "connect_stream",
	})
	if err != nil {
		_ = targetLn.Close()
		tb.Fatalf("new session: %v", err)
	}

	targetPort := uint16(targetLn.Addr().(*net.TCPAddr).Port)
	conn, err := session.DialContext(waitCtx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", targetPort))
	if err != nil {
		_ = session.Close()
		_ = targetLn.Close()
		tb.Fatalf("dial connect-stream: %v", err)
	}

	return &connectStreamHarness{
		conn:     wrapConnectStreamHarnessConn(link, conn),
		session:  session,
		targetLn: targetLn,
		closeFn: func() {
			_ = session.Close()
			_ = targetLn.Close()
		},
	}
}

func startConnectStreamDownloadHarness(tb testing.TB, link bidiLink, opts ...connectStreamHarnessOpts) *connectStreamHarness {
	tb.Helper()
	var o connectStreamHarnessOpts
	if len(opts) > 0 {
		o = opts[0]
	}
	applyConnectStreamHarnessEnv(tb, o)
	cleanupHook := applyConnectStreamTunnelHook(o)
	tb.Cleanup(cleanupHook)
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("remote listen: %v", err)
	}
	buf := make([]byte, 256*1024)
	go func() {
		for {
			c, err := targetLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				go func() { _, _ = io.Copy(io.Discard, c) }()
				deadline := time.Now().Add(30 * time.Second)
				for time.Now().Before(deadline) {
					if _, err := c.Write(buf); err != nil {
						return
					}
				}
			}(c)
		}
	}()

	proxyPort := startInProcessTCPConnectProxy(tb, connectStreamRelayHandler)
	waitCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	tb.Cleanup(cancel)

	session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
		Server:              "127.0.0.1",
		ServerPort:          uint16(proxyPort),
		MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
		TCPTransport:        "connect_stream",
	})
	if err != nil {
		_ = targetLn.Close()
		tb.Fatalf("new session: %v", err)
	}

	targetPort := uint16(targetLn.Addr().(*net.TCPAddr).Port)
	conn, err := session.DialContext(waitCtx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", targetPort))
	if err != nil {
		_ = session.Close()
		_ = targetLn.Close()
		tb.Fatalf("dial connect-stream: %v", err)
	}

	return &connectStreamHarness{
		conn:     wrapConnectStreamHarnessConn(link, conn),
		session:  session,
		targetLn: targetLn,
		closeFn: func() {
			_ = session.Close()
			_ = targetLn.Close()
		},
	}
}

// connectStreamParallelPool is one CONNECT-stream session for iperf -P N parallel dials (S5).
type connectStreamParallelPool struct {
	session    ClientSession
	targetPort uint16
	link       bidiLink
	closeFn    func()
}

func startConnectStreamParallelPool(tb testing.TB, link bidiLink) *connectStreamParallelPool {
	tb.Helper()
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("remote listen: %v", err)
	}
	buf := make([]byte, 256*1024)
	go func() {
		for {
			c, err := targetLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				go func() { _, _ = io.Copy(io.Discard, c) }()
				deadline := time.Now().Add(30 * time.Second)
				for time.Now().Before(deadline) {
					if _, err := c.Write(buf); err != nil {
						return
					}
				}
			}(c)
		}
	}()

	proxyPort := startInProcessTCPConnectProxy(tb, connectStreamRelayHandler)
	waitCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	tb.Cleanup(cancel)

	session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
		Server:              "127.0.0.1",
		ServerPort:          uint16(proxyPort),
		MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
		TCPTransport:        "connect_stream",
	})
	if err != nil {
		_ = targetLn.Close()
		tb.Fatalf("new session: %v", err)
	}

	return &connectStreamParallelPool{
		session:    session,
		targetPort: uint16(targetLn.Addr().(*net.TCPAddr).Port),
		link:       link,
		closeFn: func() {
			_ = session.Close()
			_ = targetLn.Close()
		},
	}
}

func (p *connectStreamParallelPool) dial(ctx context.Context) (net.Conn, error) {
	conn, err := p.session.DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", p.targetPort))
	if err != nil {
		return nil, err
	}
	return wrapConnectStreamHarnessConn(p.link, conn), nil
}

func (p *connectStreamParallelPool) close() {
	if p.closeFn != nil {
		p.closeFn()
	}
}

// waitConnectStreamRecycleReady gives the MASQUE session time to finish tunnel teardown
// after bulk upload close before a fresh CONNECT-stream dial (S45).
func waitConnectStreamRecycleReady(t *testing.T, pool *connectStreamParallelPool) {
	t.Helper()
	if pool == nil || pool.session == nil {
		return
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		conn, err := pool.dial(ctx)
		cancel()
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("session not ready for recycle dial after upload teardown")
}

// TestMasqueConnectStreamLocalizeRecycle verifies bulk upload teardown on one CONNECT-stream
// tunnel does not poison the shared MASQUE session before a fresh download flow (S45).
func TestMasqueConnectStreamLocalizeRecycle(t *testing.T) {
	const uploadDur = 300 * time.Millisecond
	const downloadDur = localizeBenchDuration

	pool := startConnectStreamParallelPool(t, instantBidiLink{})
	defer pool.close()

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	upConn, err := pool.dial(ctx)
	if err != nil {
		t.Fatalf("dial upload: %v", err)
	}
	upBytes, upMbps, err := measureTCPUploadMbps(upConn, uploadDur)
	if err != nil {
		t.Fatalf("upload bench: %v", err)
	}
	if err := upConn.Close(); err != nil {
		t.Fatalf("close upload conn: %v", err)
	}
	waitConnectStreamRecycleReady(t, pool)

	downConn, err := pool.dial(ctx)
	if err != nil {
		t.Fatalf("dial download after recycle: %v", err)
	}
	defer downConn.Close()
	downBytes, downMbps, err := measureTCPDownloadWriteToMbps(downConn, downloadDur)
	if err != nil {
		t.Fatalf("download bench after recycle: %v", err)
	}
	t.Logf("connect-stream recycle upload: %.1f Mbit/s (%d bytes)", upMbps, upBytes)
	t.Logf("connect-stream recycle download WriteTo: %.1f Mbit/s (%d bytes)", downMbps, downBytes)
	if downMbps < connectStreamLocalizeFastMbps {
		t.Fatalf("download after upload recycle slow: %.1f Mbit/s (want >= %.0f)", downMbps, connectStreamLocalizeFastMbps)
	}
}

func connectStreamRelayHandler(targetHost, targetPort string, r *http.Request, w http.ResponseWriter) {
	upstream, err := net.DialTimeout("tcp", net.JoinHostPort(targetHost, targetPort), 2*time.Second)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	defer upstream.Close()
	_ = upstream.SetDeadline(time.Now().Add(30 * time.Second))
	w.WriteHeader(http.StatusOK)
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
	_ = strm.RelayTCPTunnel(r.Context(), upstream, r.Body, w)
}

func benchConnectStreamUploadLayer(t *testing.T, layer string, link bidiLink, duration time.Duration) connectStreamBenchResult {
	t.Helper()
	if layer == "L0" {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return connectStreamBenchResult{layer: layer, err: err}
		}
		defer ln.Close()
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			_, _ = io.Copy(io.Discard, c)
		}()
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			return connectStreamBenchResult{layer: layer, err: err}
		}
		defer conn.Close()
		n, mbps, err := measureTCPUploadMbps(conn, duration)
		return connectStreamBenchResult{layer: layer, mbps: mbps, bytes: n, err: err}
	}

	h := startConnectStreamUploadHarness(t, link)
	defer h.close()
	n, mbps, err := measureTCPUploadMbps(h.conn, duration)
	return connectStreamBenchResult{layer: layer, mbps: mbps, bytes: n, err: err}
}

func benchConnectStreamDownloadLayer(t *testing.T, layer string, link bidiLink, duration time.Duration) connectStreamBenchResult {
	t.Helper()
	if layer == "L0" {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return connectStreamBenchResult{layer: layer, err: err}
		}
		defer ln.Close()
		buf := make([]byte, 256*1024)
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			deadline := time.Now().Add(30 * time.Second)
			for time.Now().Before(deadline) {
				if _, err := c.Write(buf); err != nil {
					return
				}
			}
		}()
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			return connectStreamBenchResult{layer: layer, err: err}
		}
		defer conn.Close()
		n, mbps, err := measureTCPDownloadMbps(conn, duration)
		return connectStreamBenchResult{layer: layer, mbps: mbps, bytes: n, err: err}
	}

	h := startConnectStreamDownloadHarness(t, link)
	defer h.close()
	n, mbps, err := measureTCPDownloadMbps(h.conn, duration)
	return connectStreamBenchResult{layer: layer, mbps: mbps, bytes: n, err: err}
}

func benchConnectStreamDownloadLayerWriteTo(t *testing.T, layer string, link bidiLink, duration time.Duration) connectStreamBenchResult {
	t.Helper()
	if layer == "L0" {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return connectStreamBenchResult{layer: layer, err: err}
		}
		defer ln.Close()
		buf := make([]byte, 256*1024)
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			deadline := time.Now().Add(30 * time.Second)
			for time.Now().Before(deadline) {
				if _, err := c.Write(buf); err != nil {
					return
				}
			}
		}()
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			return connectStreamBenchResult{layer: layer, err: err}
		}
		defer conn.Close()
		n, mbps, err := measureTCPDownloadWriteToMbps(readAsWriterTo{conn}, duration)
		return connectStreamBenchResult{layer: layer, mbps: mbps, bytes: n, err: err}
	}

	h := startConnectStreamDownloadHarness(t, link)
	defer h.close()
	n, mbps, err := measureTCPDownloadWriteToMbps(h.conn, duration)
	return connectStreamBenchResult{layer: layer, mbps: mbps, bytes: n, err: err}
}

func verdictConnectStreamDownload(l0, l1, l3 connectStreamBenchResult) string {
	switch {
	case !l0.ok() || !l1.ok() || !l3.ok():
		return "FAIL: bench error"
	case l1.mbps >= connectStreamLocalizeFastMbps && l3.mbps >= connectStreamLocalizeUploadWindowedMin && l3.mbps <= connectStreamLocalizeUploadWindowedMax:
		return "masque connect-stream bidi: L1 fast download, L3 windowed ~64KiB/RTT band → stream credit/RTT on one bidi HTTP/3 leg (not buffer size)"
	case l1.mbps < connectStreamLocalizeFastMbps && l0.mbps >= connectStreamLocalizeFastMbps:
		return "masque connect-stream: L0 fast, L1 download slow → tunnel relay or streamConn path (not wire RTT)"
	case l1.mbps >= connectStreamLocalizeFastMbps && l3.mbps > connectStreamLocalizeUploadWindowedMax:
		return "L3 window model did not reproduce download ceiling (harness calibration)"
	default:
		return "inconclusive: review download layer Mbps"
	}
}

func verdictConnectStreamBottleneck(l0, l1, l2, l3 connectStreamBenchResult) string {
	switch {
	case !l0.ok() || !l1.ok() || !l2.ok() || !l3.ok():
		return "FAIL: bench error"
	case l0.mbps < connectStreamLocalizeFastMbps:
		return "L0 raw TCP slow → bench environment or loopback regression"
	case l2.mbps < connectStreamLocalizeFastMbps:
		return "L2 wide-window upload slow → MASQUE path not unlimited (false ceiling suspect)"
	case l1.mbps >= connectStreamLocalizeFastMbps && l3.mbps >= connectStreamLocalizeUploadWindowedMin && l3.mbps <= connectStreamLocalizeUploadWindowedMax:
		return "masque connect-stream bidi: L1 fast, L3 windowed ~64KiB/RTT band → stream credit/RTT on one bidi HTTP/3 leg (not buffer size)"
	case l1.mbps < connectStreamLocalizeFastMbps && l0.mbps >= connectStreamLocalizeFastMbps:
		return "masque connect-stream: L0 fast, L1 slow → tunnel relay or streamConn path (not wire RTT)"
	case l1.mbps >= connectStreamLocalizeFastMbps && l3.mbps > connectStreamLocalizeUploadWindowedMax:
		return "L3 window model did not reproduce ceiling (harness calibration)"
	default:
		return "inconclusive: review layer Mbps"
	}
}

func assertConnectStreamFastLayer(t *testing.T, r connectStreamBenchResult) {
	t.Helper()
	if r.err != nil {
		t.Fatalf("%s: %v", r.layer, r.err)
	}
	if r.mbps < connectStreamLocalizeFastMbps {
		t.Fatalf("%s slow: %.1f Mbit/s (want >= %.0f)", r.layer, r.mbps, connectStreamLocalizeFastMbps)
	}
}

func assertConnectStreamUploadWindowedLayer(t *testing.T, r connectStreamBenchResult) {
	t.Helper()
	if r.err != nil {
		t.Fatalf("%s: %v", r.layer, r.err)
	}
	if r.mbps < connectStreamLocalizeUploadWindowedMin || r.mbps > connectStreamLocalizeUploadWindowedMax {
		t.Fatalf("%s windowed upload: %.1f Mbit/s (want %.0f–%.0f)", r.layer, r.mbps, connectStreamLocalizeUploadWindowedMin, connectStreamLocalizeUploadWindowedMax)
	}
}

func assertConnectStreamDownloadKPILayer(t *testing.T, r connectStreamBenchResult) {
	t.Helper()
	assertConnectStreamWindowedCeilingBand(t, r.mbps, r.layer+" download WriteTo")
}

// TestConnectStreamLocalizeL256WindowSensitivity (S43): 256 KiB bidi credit must exceed the
// bench-shaped 64 KiB ceiling band, proving the harness window model is size-sensitive.
func TestConnectStreamLocalizeL256WindowSensitivity(t *testing.T) {
	const duration = localizeBenchDuration

	l3 := benchConnectStreamUploadLayer(t, "L3", benchWindowedBidiLink(), duration)
	l256 := benchConnectStreamUploadLayer(t, "L256", benchWindowedBidiLinkL256(), duration)
	for _, r := range []connectStreamBenchResult{l3, l256} {
		if r.err != nil {
			t.Fatalf("%s: %v", r.layer, r.err)
		}
		t.Logf("connect-stream L256 sensitivity %s upload: %.1f Mbit/s (%d bytes)", r.layer, r.mbps, r.bytes)
	}

	assertConnectStreamUploadWindowedLayer(t, l3)
	if l256.mbps <= connectStreamLocalizeUploadWindowedMax {
		t.Fatalf("L256 upload %.1f Mbit/s did not escape upload ceiling max %.0f (window model insensitive)", l256.mbps, connectStreamLocalizeUploadWindowedMax)
	}
	if l256.mbps < l3.mbps*2 {
		t.Fatalf("L256 upload %.1f Mbit/s want >= 2× L3 %.1f (window sensitivity)", l256.mbps, l3.mbps)
	}
}

// TestMasqueConnectStreamLocalizeBottleneck localizes CONNECT-stream throughput (~70 down field symptom).
func TestMasqueConnectStreamLocalizeBottleneck(t *testing.T) {
	const duration = localizeBenchDuration

	l0 := benchConnectStreamUploadLayer(t, "L0", nil, duration)
	l1 := benchConnectStreamUploadLayer(t, "L1", instantBidiLink{}, duration)
	l2 := benchConnectStreamUploadLayer(t, "L2", benchWindowedWideBidiLink(), duration)
	l3 := benchConnectStreamUploadLayer(t, "L3", benchWindowedBidiLink(), duration)
	l256 := benchConnectStreamUploadLayer(t, "L256", benchWindowedBidiLinkL256(), duration)

	for _, r := range []connectStreamBenchResult{l0, l1, l2, l3, l256} {
		if r.err != nil {
			t.Fatalf("%s: %v", r.layer, r.err)
		}
		t.Logf("connect-stream localize %s upload: %.1f Mbit/s (%d bytes)", r.layer, r.mbps, r.bytes)
	}

	assertConnectStreamFastLayer(t, l0) // S46: raw TCP baseline
	if l2.mbps < connectStreamLocalizeWideUploadMinMbps {
		t.Fatalf("L2 wide upload slow: %.1f Mbit/s (want >= %.0f)", l2.mbps, connectStreamLocalizeWideUploadMinMbps)
	}
	if l1.mbps < connectStreamLocalizeInstantUploadMinMbps {
		t.Fatalf("L1 upload slow: %.1f Mbit/s (want >= %.0f)", l1.mbps, connectStreamLocalizeInstantUploadMinMbps)
	}
	assertConnectStreamUploadWindowedLayer(t, l3)
	if l256.mbps <= l3.mbps {
		t.Fatalf("L256 upload %.1f Mbit/s must exceed L3 %.1f (S43 window sensitivity)", l256.mbps, l3.mbps)
	}

	v := verdictConnectStreamBottleneck(l0, l1, l2, l3)
	t.Logf("connect-stream localize verdict: %s", v)
	if v == "inconclusive: review layer Mbps" {
		t.Fatalf("bottleneck verdict inconclusive: L0=%.1f L1=%.1f L2=%.1f L3=%.1f", l0.mbps, l1.mbps, l2.mbps, l3.mbps)
	}

	dlL1 := benchConnectStreamDownloadLayerWriteTo(t, "L1", instantBidiLink{}, duration)
	dlL3 := benchConnectStreamDownloadLayerWriteTo(t, "L3", benchWindowedBidiLink(), duration) // S47
	for _, r := range []connectStreamBenchResult{dlL1, dlL3} {
		if r.err != nil {
			t.Fatalf("%s download WriteTo: %v", r.layer, r.err)
		}
		t.Logf("connect-stream localize %s download WriteTo: %.1f Mbit/s (%d bytes)", r.layer, r.mbps, r.bytes)
	}
	assertConnectStreamFastLayer(t, dlL1)
	assertConnectStreamDownloadKPILayer(t, dlL3) // S47: L3 download KPI
}

// TestMasqueConnectStreamLocalizeBottleneckWriteTo (S94): full L0–L3 download matrix via WriteTo
// (upload matrix in TestMasqueConnectStreamLocalizeBottleneck; download must mirror prod path).
func TestMasqueConnectStreamLocalizeBottleneckWriteTo(t *testing.T) {
	const duration = localizeBenchDuration

	l0 := benchConnectStreamDownloadLayerWriteTo(t, "L0", nil, duration)
	l1 := benchConnectStreamDownloadLayerWriteTo(t, "L1", instantBidiLink{}, duration)
	l2 := benchConnectStreamDownloadLayerWriteTo(t, "L2", benchWindowedWideBidiLink(), duration)
	l3 := benchConnectStreamDownloadLayerWriteTo(t, "L3", benchWindowedBidiLink(), duration)
	l256 := benchConnectStreamDownloadLayerWriteTo(t, "L256", benchWindowedBidiLinkL256(), duration)

	for _, r := range []connectStreamBenchResult{l0, l1, l2, l3, l256} {
		if r.err != nil {
			t.Fatalf("%s download WriteTo: %v", r.layer, r.err)
		}
		t.Logf("connect-stream bottleneck WriteTo %s download: %.1f Mbit/s (%d bytes)", r.layer, r.mbps, r.bytes)
	}

	assertConnectStreamFastLayer(t, l0)
	assertConnectStreamFastLayer(t, l2)
	assertConnectStreamFastLayer(t, l1)
	assertConnectStreamDownloadKPILayer(t, l3)
	// L256 narrower bench may be below L3 download with eager WINDOW — sensitivity checked on upload matrix (S43).

	v := verdictConnectStreamBottleneck(l0, l1, l2, l3)
	t.Logf("connect-stream bottleneck WriteTo download verdict: %s", v)
	if v == "inconclusive: review layer Mbps" {
		t.Fatalf("bottleneck WriteTo download verdict inconclusive: L0=%.1f L1=%.1f L2=%.1f L3=%.1f",
			l0.mbps, l1.mbps, l2.mbps, l3.mbps)
	}
}

// TestMasqueConnectStreamLocalizeDownload checks instant L1 and windowed L3 download bands.
func TestMasqueConnectStreamLocalizeDownload(t *testing.T) {
	const duration = 400 * time.Millisecond

	l0 := benchConnectStreamDownloadLayer(t, "L0", nil, duration)
	l1 := benchConnectStreamDownloadLayer(t, "L1", instantBidiLink{}, duration)
	l3 := benchConnectStreamDownloadLayer(t, "L3", benchWindowedBidiLink(), duration)

	for _, r := range []connectStreamBenchResult{l0, l1, l3} {
		if r.err != nil {
			t.Fatalf("%s: %v", r.layer, r.err)
		}
		t.Logf("connect-stream localize download %s: %.1f Mbit/s (%d bytes)", r.layer, r.mbps, r.bytes)
	}

	if l1.mbps < connectStreamLocalizeFastMbps {
		t.Fatalf("download L1 slow: %.1f Mbit/s (want >= %.0f)", l1.mbps, connectStreamLocalizeFastMbps)
	}

	v := verdictConnectStreamDownload(l0, l1, l3)
	t.Logf("connect-stream localize download verdict: %s", v)
}

// TestMasqueConnectStreamLocalizeDownloadWriteTo checks instant L1 and windowed L3 via WriteTo (S3).
func TestMasqueConnectStreamLocalizeDownloadWriteTo(t *testing.T) {
	const duration = localizeBenchDuration

	l0 := benchConnectStreamDownloadLayerWriteTo(t, "L0", nil, duration)
	l1 := benchConnectStreamDownloadLayerWriteTo(t, "L1", instantBidiLink{}, duration)
	l3 := benchConnectStreamDownloadLayerWriteTo(t, "L3", benchWindowedBidiLink(), duration)

	for _, r := range []connectStreamBenchResult{l0, l1, l3} {
		if r.err != nil {
			t.Fatalf("%s WriteTo: %v", r.layer, r.err)
		}
		t.Logf("connect-stream WriteTo download %s: %.1f Mbit/s (%d bytes)", r.layer, r.mbps, r.bytes)
	}

	if l1.mbps < connectStreamLocalizeFastMbps {
		t.Fatalf("WriteTo L1 slow: %.1f Mbit/s (want >= %.0f)", l1.mbps, connectStreamLocalizeFastMbps)
	}
	assertConnectStreamDownloadKPILayer(t, l3)

	v := verdictConnectStreamDownload(l0, l1, l3)
	t.Logf("connect-stream WriteTo download verdict: %s", v)
}

// TestMasqueConnectStreamUploadL2WideWindowBand (S93): L2 wide bidi credit (16 MiB) must stay in the
// fast upload band — escapes 64 KiB ceiling without regressing to L3 windowed throughput.
func TestMasqueConnectStreamUploadL2WideWindowBand(t *testing.T) {
	r := benchConnectStreamUploadLayer(t, "L2", benchWindowedWideBidiLink(), localizeBenchDuration)
	if r.err != nil {
		t.Fatalf("L2 wide upload: %v", r.err)
	}
	if r.bytes < localizeBenchMinBytes {
		t.Fatalf("L2 wide upload bytes=%d want >= %d", r.bytes, localizeBenchMinBytes)
	}
	t.Logf("connect-stream L2 wide window upload: %.1f Mbit/s (%d bytes)", r.mbps, r.bytes)
	if r.mbps < connectStreamLocalizeWideUploadMinMbps {
		t.Fatalf("L2 wide upload slow: %.1f Mbit/s (want >= %.0f)", r.mbps, connectStreamLocalizeWideUploadMinMbps)
	}

	l3 := benchConnectStreamUploadLayer(t, "L3", benchWindowedBidiLink(), localizeBenchDuration)
	if l3.err != nil {
		t.Fatalf("L3 upload: %v", l3.err)
	}
	if r.mbps <= l3.mbps*2 {
		t.Fatalf("L2 wide upload %.1f Mbit/s want >> L3 ceiling %.1f (wide window ineffective)", r.mbps, l3.mbps)
	}
}

// TestMasqueConnectStreamInstantDownloadExceedsVPSKPI verifies unlimited bidi download exceeds
// field KPI target (21 Mbit/s) — stack can deliver; wire scheduling is the field gap.
func TestMasqueConnectStreamInstantDownloadExceedsVPSKPI(t *testing.T) {
	const duration = 400 * time.Millisecond
	r := benchConnectStreamDownloadLayer(t, "L1", instantBidiLink{}, duration)
	if r.err != nil {
		t.Fatalf("L1 download: %v", r.err)
	}
	t.Logf("connect-stream instant download: %.1f Mbit/s", r.mbps)
	if r.mbps <= connectStreamVPSKPITargetDownMbps {
		t.Fatalf("instant download %.1f Mbit/s (want > %.0f VPS KPI)", r.mbps, connectStreamVPSKPITargetDownMbps)
	}
}

// TestMasqueConnectStreamLocalizeDuplex checks download continues while upload pulses on one bidi tunnel.
func TestMasqueConnectStreamLocalizeDuplex(t *testing.T) {
	runConnectStreamDuplexBench(t, instantBidiLink{}, connectStreamLocalizeFastMbps/4)
}

// TestMasqueConnectStreamLocalizeDuplexWindowed checks windowed bidi credit still allows download under upload pulses.
func TestMasqueConnectStreamLocalizeDuplexWindowed(t *testing.T) {
	runConnectStreamDuplexBench(t, benchWindowedBidiLink(), connectStreamLocalizeDownloadKPIMin/2)
}

func runConnectStreamDuplexBench(t *testing.T, link bidiLink, minMbps float64) {
	t.Helper()
	runConnectStreamDuplexBenchRead(t, link, minMbps)
}

func runConnectStreamDuplexBenchRead(t *testing.T, link bidiLink, minMbps float64) {
	t.Helper()
	const duration = 400 * time.Millisecond
	const pulseBytes = 32 * 1024

	h := startConnectStreamDownloadHarness(t, link)
	defer h.close()

	downloadDone := make(chan connectStreamBenchResult, 1)
	go func() {
		n, mbps, err := measureTCPDownloadMbps(h.conn, duration)
		downloadDone <- connectStreamBenchResult{layer: "download", mbps: mbps, bytes: n, err: err}
	}()

	pulse := make([]byte, pulseBytes)
	pulseDeadline := time.Now().Add(duration)
	for time.Now().Before(pulseDeadline) {
		if _, err := h.conn.Write(pulse); err != nil {
			t.Fatalf("upload pulse: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	dl := <-downloadDone
	if dl.err != nil {
		t.Fatalf("duplex download: %v", dl.err)
	}
	t.Logf("connect-stream duplex download: %.1f Mbit/s (%d bytes)", dl.mbps, dl.bytes)
	if dl.mbps < minMbps {
		t.Fatalf("duplex download stalled: %.1f Mbit/s (want >= %.0f)", dl.mbps, minMbps)
	}
}

func runConnectStreamDuplexWriteToBench(t *testing.T, link bidiLink, minMbps float64, opts ...connectStreamHarnessOpts) connectStreamBenchResult {
	t.Helper()
	const duration = localizeBenchDuration
	const pulseBytes = 32 * 1024

	h := startConnectStreamDownloadHarness(t, link, opts...)
	defer h.close()

	downloadDone := make(chan connectStreamBenchResult, 1)
	go func() {
		n, mbps, err := measureTCPDownloadWriteToMbps(h.conn, duration)
		downloadDone <- connectStreamBenchResult{layer: "download", mbps: mbps, bytes: n, err: err}
	}()

	pulse := make([]byte, pulseBytes)
	pulseDeadline := time.Now().Add(duration)
	for time.Now().Before(pulseDeadline) {
		if _, err := h.conn.Write(pulse); err != nil {
			t.Fatalf("upload pulse: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	dl := <-downloadDone
	if dl.err != nil {
		t.Fatalf("duplex WriteTo download: %v", dl.err)
	}
	t.Logf("connect-stream duplex WriteTo download: %.1f Mbit/s (%d bytes)", dl.mbps, dl.bytes)
	if dl.mbps < minMbps {
		t.Fatalf("duplex WriteTo download stalled: %.1f Mbit/s (want >= %.0f)", dl.mbps, minMbps)
	}
	return dl
}

// TestH3DuplexConnWakeReceiveVsDeliveryEnvMatrix (S64): upload vs download BidiWakeSink events
// on full CONNECT-stream harness under MASQUE_H3_BIDI_UPLOAD_WAKE env.
func TestH3DuplexConnWakeReceiveVsDeliveryEnvMatrix(t *testing.T) {
	cases := []struct {
		name      string
		wake      string
		wantWakes bool
	}{
		{"wake_on", "1", true},
		{"wake_off", "0", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("MASQUE_H3_BIDI_DUPLEX_COORD", "1")
			t.Setenv("MASQUE_H3_BIDI_UPLOAD_WAKE", tc.wake)
			t.Setenv("MASQUE_H3_BIDI_DOWNLOAD_WAKE", tc.wake)

			inj := newLocalizeInjectors()
			dl := runConnectStreamDuplexWriteToBench(
				t,
				benchWindowedBidiLink(),
				connectStreamLocalizeDownloadKPIMin,
				inj.connectStreamOpts(),
			)
			assertConnectStreamWindowedCeilingBand(t, dl.mbps, "duplex WriteTo download (S64 wake matrix)")

			uploadWakes := inj.BidiWake.Upload.Load()
			downloadWakes := inj.BidiWake.Download.Load()
			t.Logf("duplex wake matrix wake=%s upload=%d download=%d", tc.wake, uploadWakes, downloadWakes)

			if tc.wantWakes {
				if uploadWakes == 0 {
					t.Fatal("expected upload-side BidiWakeSink events with wake env on")
				}
				if downloadWakes == 0 {
					t.Fatal("expected download-delivery BidiWakeSink events with wake env on")
				}
				return
			}
			if uploadWakes != 0 || downloadWakes != 0 {
				t.Fatalf("expected no BidiWakeSink events with wake env off, upload=%d download=%d", uploadWakes, downloadWakes)
			}
		})
	}
}

// TestConnectStreamLocalizeH3WakeAndFlushMetrics (S42): windowed CONNECT-stream download records
// BidiWakeSink delivery events and meets localize bench byte/Mbps contract under wake env.
func TestConnectStreamLocalizeH3WakeAndFlushMetrics(t *testing.T) {
	t.Setenv("MASQUE_H3_BIDI_DUPLEX_COORD", "1")
	t.Setenv("MASQUE_H3_BIDI_UPLOAD_WAKE", "1")

	inj := newLocalizeInjectors()
	h := startConnectStreamDownloadHarness(t, benchWindowedBidiLink(), inj.connectStreamOpts())
	defer h.close()

	n, mbps, err := measureTCPDownloadWriteToMbps(h.conn, localizeBenchDuration)
	if err != nil {
		t.Fatalf("windowed WriteTo download: %v", err)
	}
	if n < localizeBenchMinBytes {
		t.Fatalf("bytes=%d want >= %d", n, localizeBenchMinBytes)
	}
	assertConnectStreamWindowedCeilingBand(t, mbps, "download WriteTo (S42)")

	downloadWakes := inj.BidiWake.Download.Load()
	t.Logf("connect-stream H3 wake metrics: downloadWakes=%d bytes=%d mbps=%.1f", downloadWakes, n, mbps)
	if downloadWakes == 0 {
		t.Fatal("expected download BidiWakeSink events with MASQUE_H3_BIDI_UPLOAD_WAKE=1")
	}
}

// unwrapH3TunnelConn walks masque wrappers to the underlying *h3.TunnelConn.
func unwrapH3TunnelConn(conn net.Conn) (*h3.TunnelConn, bool) {
	for conn != nil {
		if tc, ok := conn.(*h3.TunnelConn); ok {
			return tc, true
		}
		switch c := conn.(type) {
		case *strm.TunnelConn:
			conn = c.Inner
		default:
			if inner, ok := h3.BidiWindowInner(conn); ok {
				conn = inner
			} else {
				return nil, false
			}
		}
	}
	return nil, false
}

// TestMasqueConnectStreamPipeUploadVsBidiLocalizeDownload (S89) compares bidi stream upload
// vs legacy pipe upload on concurrent WriteTo download under the windowed bidi credit model.
func TestMasqueConnectStreamPipeUploadVsBidiLocalizeDownload(t *testing.T) {
	t.Setenv("MASQUE_H3_BIDI_DUPLEX_COORD", "1")

	t.Run("bidi_uses_h3_stream_windowed_ceiling", func(t *testing.T) {
		h := startConnectStreamDownloadHarness(t, benchWindowedBidiLink())
		defer h.close()
		tc, ok := unwrapH3TunnelConn(h.conn)
		if !ok {
			t.Fatal("expected *h3.TunnelConn under harness conn")
		}
		if !tc.UsesH3Stream() {
			t.Fatal("bidi mode must share one http3.Stream (UsesH3Stream=true)")
		}
		dl := runConnectStreamDuplexWriteToBenchOnConn(t, h.conn, connectStreamLocalizeDownloadKPIMin/2)
		assertConnectStreamWindowedCeilingBand(t, dl.mbps, "bidi windowed duplex WriteTo")
	})

	t.Run("pipe_upload_decoupled_instant_download", func(t *testing.T) {
		h := startConnectStreamDownloadHarness(t, instantBidiLink{}, connectStreamHarnessOpts{PipeUpload: true})
		defer h.close()
		tc, ok := unwrapH3TunnelConn(h.conn)
		if !ok {
			t.Fatal("expected *h3.TunnelConn under harness conn")
		}
		if tc.UsesH3Stream() {
			t.Fatal("pipe upload must not share http3.Stream for upload (UsesH3Stream=false)")
		}
		dl := runConnectStreamDuplexWriteToBenchOnConn(t, h.conn, connectStreamVPSKPITargetDownMbps)
		if dl.mbps <= connectStreamVPSKPITargetDownMbps {
			t.Fatalf("pipe upload concurrent WriteTo download: %.1f Mbit/s (want > %.0f VPS KPI)", dl.mbps, connectStreamVPSKPITargetDownMbps)
		}
	})

	t.Run("pipe_upload_not_stalled_under_WriteTo_download", func(t *testing.T) {
		h := startConnectStreamDownloadHarness(t, instantBidiLink{}, connectStreamHarnessOpts{PipeUpload: true})
		defer h.close()
		upMbps := runConnectStreamConcurrentUploadMbps(t, h.conn, localizeBenchDuration)
		t.Logf("pipe upload concurrent upload: %.1f Mbit/s", upMbps)
		// In-process concurrent duplex caps near field ceiling (~15 Mbit/s); guard against upload hang (<<4).
		if upMbps < connectStreamLocalizeUploadWindowedMin {
			t.Fatalf("pipe upload stalled under concurrent download: %.1f Mbit/s (want >= %.0f)", upMbps, connectStreamLocalizeUploadWindowedMin)
		}
	})
}

// TestMasqueConnectStreamHypothesisHD1DuplexQuota (S91) guards the thin WriteTo path without
// removed H-D1 duplex quota: instant download exceeds VPS KPI; windowed duplex stays in ceiling band.
func TestMasqueConnectStreamHypothesisHD1DuplexQuota(t *testing.T) {
	t.Setenv("MASQUE_H3_BIDI_DUPLEX_COORD", "1")

	instant := benchConnectStreamDownloadLayerWriteTo(t, "L1", instantBidiLink{}, localizeBenchDuration)
	if instant.err != nil {
		t.Fatalf("instant WriteTo download: %v", instant.err)
	}
	t.Logf("H-D1 guard instant WriteTo: %.1f Mbit/s", instant.mbps)
	if instant.mbps <= connectStreamVPSKPITargetDownMbps {
		t.Fatalf("without duplex quota instant download %.1f Mbit/s (want > %.0f VPS KPI)", instant.mbps, connectStreamVPSKPITargetDownMbps)
	}

	windowed := benchConnectStreamDownloadLayerWriteTo(t, "L3", benchWindowedBidiLink(), localizeBenchDuration)
	if windowed.err != nil {
		t.Fatalf("windowed WriteTo download: %v", windowed.err)
	}
	t.Logf("H-D1 guard windowed WriteTo: %.1f Mbit/s", windowed.mbps)
	if windowed.mbps <= connectStreamVPSKPITargetDownMbps {
		t.Fatalf("windowed ceiling without quota: %.1f Mbit/s (want > %.0f — quota was not root cause)", windowed.mbps, connectStreamVPSKPITargetDownMbps)
	}

	duplex := runConnectStreamDuplexWriteToBench(t, benchWindowedBidiLink(), connectStreamLocalizeDownloadKPIMin/2)
	t.Logf("H-D1 guard duplex WriteTo: %.1f Mbit/s", duplex.mbps)
}

func runConnectStreamDuplexWriteToBenchOnConn(t *testing.T, conn net.Conn, minMbps float64) connectStreamBenchResult {
	t.Helper()
	const duration = localizeBenchDuration
	const pulseBytes = 32 * 1024

	downloadDone := make(chan connectStreamBenchResult, 1)
	go func() {
		n, mbps, err := measureTCPDownloadWriteToMbps(conn, duration)
		downloadDone <- connectStreamBenchResult{layer: "download", mbps: mbps, bytes: n, err: err}
	}()

	pulse := make([]byte, pulseBytes)
	pulseDeadline := time.Now().Add(duration)
	for time.Now().Before(pulseDeadline) {
		if _, err := conn.Write(pulse); err != nil {
			t.Fatalf("upload pulse: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	dl := <-downloadDone
	if dl.err != nil {
		t.Fatalf("duplex WriteTo download: %v", dl.err)
	}
	t.Logf("connect-stream duplex WriteTo download: %.1f Mbit/s (%d bytes)", dl.mbps, dl.bytes)
	if dl.mbps < minMbps {
		t.Fatalf("duplex WriteTo download stalled: %.1f Mbit/s (want >= %.0f)", dl.mbps, minMbps)
	}
	return dl
}

func runConnectStreamConcurrentUploadMbps(t *testing.T, conn net.Conn, duration time.Duration) float64 {
	t.Helper()
	downloadDone := make(chan struct{})
	go func() {
		defer close(downloadDone)
		if wt, ok := conn.(io.WriterTo); ok {
			sink := &benchWriteToSink{deadline: time.Now().Add(duration)}
			_, _ = wt.WriteTo(sink)
		}
	}()

	buf := make([]byte, 256*1024)
	var total int64
	deadline := time.Now().Add(duration)
	for time.Now().Before(deadline) {
		n, err := conn.Write(buf)
		if n > 0 {
			total += int64(n)
		}
		if err != nil {
			break
		}
	}
	<-downloadDone
	secs := duration.Seconds()
	if secs <= 0 {
		secs = 1
	}
	return float64(total*8) / secs / 1e6
}
