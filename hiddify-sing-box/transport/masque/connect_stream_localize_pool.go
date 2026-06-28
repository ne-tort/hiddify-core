package masque

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing-box/transport/masque/h3"
)
type connectStreamHarness struct {
	conn     net.Conn
	session  ClientSession
	targetLn net.Listener
	closeFn  func()
}

// connectStreamHarnessOpts configures in-process CONNECT-stream harness probes (S41, S89).
type connectStreamHarnessOpts struct {
	BidiWakeSink h3.BidiWakeSink
}

func wrapConnectStreamHarnessConn(link bidiLink, conn net.Conn) net.Conn {
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
