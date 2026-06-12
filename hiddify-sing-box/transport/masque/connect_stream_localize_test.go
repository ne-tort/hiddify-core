package masque

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

// connectStreamLocalize bands (Mbit/s) for in-process CONNECT-stream benches.
const (
	connectStreamLocalizeFastMbps   = 80.0
	connectStreamLocalizeCeilingMax = 28.0
	connectStreamLocalizeCeilingMin = 4.0
)

type connectStreamBenchResult struct {
	layer string
	mbps  float64
	bytes int64
	err   error
}

func (r connectStreamBenchResult) ok() bool { return r.err == nil }

// bidiLink models the HTTP/3 CONNECT-stream bidi byte pipe for localize benches.
type bidiLink interface {
	wrap(net.Conn) net.Conn
}

type instantBidiLink struct{}

func (instantBidiLink) wrap(c net.Conn) net.Conn { return c }

// windowedBidiLink limits client→server in-flight bytes and returns credit after RTT
// (bench-shaped ~64 KiB / RTT ≈ 13–15 Mbit/s at 35 ms).
type windowedBidiLink struct {
	rtt         time.Duration
	windowBytes int
}

func (w windowedBidiLink) wrap(inner net.Conn) net.Conn {
	return newWindowedBidiConn(inner, w.rtt, w.windowBytes)
}

type windowedBidiConn struct {
	inner       net.Conn
	rtt         time.Duration
	windowBytes int

	mu          sync.Mutex
	cond        *sync.Cond
	inflightC2S int
	closed      bool
}

func newWindowedBidiConn(inner net.Conn, rtt time.Duration, windowBytes int) *windowedBidiConn {
	if windowBytes <= 0 {
		windowBytes = 64 * 1024
	}
	if rtt <= 0 {
		rtt = 35 * time.Millisecond
	}
	c := &windowedBidiConn{
		inner:       inner,
		rtt:         rtt,
		windowBytes: windowBytes,
	}
	c.cond = sync.NewCond(&c.mu)
	return c
}

func (c *windowedBidiConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	total := 0
	for len(p) > 0 {
		chunk := len(p)
		if chunk > c.windowBytes {
			chunk = c.windowBytes
		}
		c.mu.Lock()
		for c.inflightC2S+chunk > c.windowBytes && !c.closed {
			c.cond.Wait()
		}
		if c.closed {
			c.mu.Unlock()
			if total > 0 {
				return total, net.ErrClosed
			}
			return 0, net.ErrClosed
		}
		c.inflightC2S += chunk
		c.mu.Unlock()

		n, err := c.inner.Write(p[:chunk])
		if n > 0 {
			credit := n
			if c.rtt > 0 {
				time.AfterFunc(c.rtt, func() { c.releaseC2S(credit) })
			} else {
				c.releaseC2S(credit)
			}
		}
		if n < chunk {
			c.releaseC2S(chunk - n)
		}
		total += n
		p = p[n:]
		if err != nil {
			return total, err
		}
		if n < chunk {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}

func (c *windowedBidiConn) releaseC2S(n int) {
	c.mu.Lock()
	c.inflightC2S -= n
	if c.inflightC2S < 0 {
		c.inflightC2S = 0
	}
	c.cond.Broadcast()
	c.mu.Unlock()
}

func (c *windowedBidiConn) Read(p []byte) (int, error)  { return c.inner.Read(p) }
func (c *windowedBidiConn) Close() error                 { return c.inner.Close() }
func (c *windowedBidiConn) LocalAddr() net.Addr          { return c.inner.LocalAddr() }
func (c *windowedBidiConn) RemoteAddr() net.Addr         { return c.inner.RemoteAddr() }
func (c *windowedBidiConn) SetDeadline(t time.Time) error { return c.inner.SetDeadline(t) }
func (c *windowedBidiConn) SetReadDeadline(t time.Time) error {
	return c.inner.SetReadDeadline(t)
}
func (c *windowedBidiConn) SetWriteDeadline(t time.Time) error {
	return c.inner.SetWriteDeadline(t)
}

type connectStreamHarness struct {
	conn     net.Conn
	session  ClientSession
	targetLn net.Listener
	closeFn  func()
}

func (h *connectStreamHarness) close() {
	if h.conn != nil {
		_ = h.conn.Close()
	}
	if h.closeFn != nil {
		h.closeFn()
	}
}

func startConnectStreamUploadHarness(t *testing.T, link bidiLink) *connectStreamHarness {
	t.Helper()
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("remote listen: %v", err)
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

	proxyPort := startInProcessTCPConnectProxy(t, connectStreamRelayHandler)
	waitCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	t.Cleanup(cancel)

	session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
		Server:              "127.0.0.1",
		ServerPort:          uint16(proxyPort),
		MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
		TCPTransport:        "connect_stream",
	})
	if err != nil {
		_ = targetLn.Close()
		t.Fatalf("new session: %v", err)
	}

	targetPort := uint16(targetLn.Addr().(*net.TCPAddr).Port)
	conn, err := session.DialContext(waitCtx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", targetPort))
	if err != nil {
		_ = session.Close()
		_ = targetLn.Close()
		t.Fatalf("dial connect-stream: %v", err)
	}

	return &connectStreamHarness{
		conn:     link.wrap(conn),
		session:  session,
		targetLn: targetLn,
		closeFn: func() {
			_ = session.Close()
			_ = targetLn.Close()
		},
	}
}

func startConnectStreamDownloadHarness(t *testing.T, link bidiLink) *connectStreamHarness {
	t.Helper()
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("remote listen: %v", err)
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

	proxyPort := startInProcessTCPConnectProxy(t, connectStreamRelayHandler)
	waitCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	t.Cleanup(cancel)

	session, err := (CoreClientFactory{}).NewSession(waitCtx, ClientOptions{
		Server:              "127.0.0.1",
		ServerPort:          uint16(proxyPort),
		MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
		TCPTransport:        "connect_stream",
	})
	if err != nil {
		_ = targetLn.Close()
		t.Fatalf("new session: %v", err)
	}

	targetPort := uint16(targetLn.Addr().(*net.TCPAddr).Port)
	conn, err := session.DialContext(waitCtx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", targetPort))
	if err != nil {
		_ = session.Close()
		_ = targetLn.Close()
		t.Fatalf("dial connect-stream: %v", err)
	}

	return &connectStreamHarness{
		conn:     link.wrap(conn),
		session:  session,
		targetLn: targetLn,
		closeFn: func() {
			_ = session.Close()
			_ = targetLn.Close()
		},
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
	_ = RelayTCPTunnel(r.Context(), upstream, r.Body, w)
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
	h := startConnectStreamDownloadHarness(t, link)
	defer h.close()
	n, mbps, err := measureTCPDownloadMbps(h.conn, duration)
	return connectStreamBenchResult{layer: layer, mbps: mbps, bytes: n, err: err}
}

func verdictConnectStreamBottleneck(l0, l1, l3 connectStreamBenchResult) string {
	switch {
	case !l0.ok() || !l1.ok() || !l3.ok():
		return "FAIL: bench error"
	case l1.mbps >= connectStreamLocalizeFastMbps && l3.mbps >= connectStreamLocalizeCeilingMin && l3.mbps <= connectStreamLocalizeCeilingMax:
		return "masque connect-stream bidi: L1 fast, L3 windowed ~64KiB/RTT band → stream credit/RTT on one bidi HTTP/3 leg (not buffer size)"
	case l1.mbps < connectStreamLocalizeFastMbps && l0.mbps >= connectStreamLocalizeFastMbps:
		return "masque connect-stream: L0 fast, L1 slow → tunnel relay or streamConn path (not wire RTT)"
	case l1.mbps >= connectStreamLocalizeFastMbps && l3.mbps > connectStreamLocalizeCeilingMax:
		return "L3 window model did not reproduce ceiling (harness calibration)"
	default:
		return "inconclusive: review layer Mbps"
	}
}

// TestMasqueConnectStreamLocalizeBottleneck localizes CONNECT-stream throughput (~70 down field symptom).
func TestMasqueConnectStreamLocalizeBottleneck(t *testing.T) {
	const duration = 400 * time.Millisecond

	l0 := benchConnectStreamUploadLayer(t, "L0", nil, duration)
	l1 := benchConnectStreamUploadLayer(t, "L1", instantBidiLink{}, duration)
	l2 := benchConnectStreamUploadLayer(t, "L2", windowedBidiLink{
		rtt:         35 * time.Millisecond,
		windowBytes: 16 << 20,
	}, duration)
	l3 := benchConnectStreamUploadLayer(t, "L3", windowedBidiLink{
		rtt:         35 * time.Millisecond,
		windowBytes: 64 * 1024,
	}, duration)

	for _, r := range []connectStreamBenchResult{l0, l1, l2, l3} {
		if r.err != nil {
			t.Fatalf("%s: %v", r.layer, r.err)
		}
		t.Logf("connect-stream localize %s upload: %.1f Mbit/s (%d bytes)", r.layer, r.mbps, r.bytes)
	}

	if l1.mbps < connectStreamLocalizeFastMbps {
		t.Fatalf("L1 upload slow: %.1f Mbit/s (want >= %.0f)", l1.mbps, connectStreamLocalizeFastMbps)
	}

	v := verdictConnectStreamBottleneck(l0, l1, l3)
	t.Logf("connect-stream localize verdict: %s", v)

	dl := benchConnectStreamDownloadLayer(t, "L1", instantBidiLink{}, duration)
	if dl.err != nil {
		t.Fatalf("L1 download: %v", dl.err)
	}
	t.Logf("connect-stream localize L1 download: %.1f Mbit/s (%d bytes)", dl.mbps, dl.bytes)
	if dl.mbps < connectStreamLocalizeFastMbps {
		t.Fatalf("L1 download slow: %.1f Mbit/s (want >= %.0f)", dl.mbps, connectStreamLocalizeFastMbps)
	}
}

// TestMasqueConnectStreamLocalizeDuplex checks download continues while upload pulses on one bidi tunnel.
func TestMasqueConnectStreamLocalizeDuplex(t *testing.T) {
	const duration = 400 * time.Millisecond
	const pulseBytes = 32 * 1024

	h := startConnectStreamDownloadHarness(t, instantBidiLink{})
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
	if dl.mbps < connectStreamLocalizeFastMbps/4 {
		t.Fatalf("duplex download stalled: %.1f Mbit/s (want >= %.0f)", dl.mbps, connectStreamLocalizeFastMbps/4)
	}
}
