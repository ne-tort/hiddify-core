package masque

// Localize L1/L3 for CONNECT-UDP: in-process HTTP/3 proxy + UDP echo; windowed QUIC datagram link @ 64 KiB / 35 ms RTT.

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/sagernet/sing-box/transport/masque/connectudp"
	M "github.com/sagernet/sing/common/metadata"
)

const (
	connectUDPLocalizeFastMbps   = 80.0
	connectUDPLocalizeBurstMinMbps = 40.0 // one-way upload on instant in-proc link
	connectUDPLocalizeCeilingMin = 4.0
	// Legacy paced probe @ docker target 8 Mbit/s — not GATE DoD (see connectUDPLegacyPaced*).
	connectUDPLocalizePacedMinMbps = connectUDPLegacyPacedMinMbps
	connectUDPLocalizePacedMaxMbps = connectUDPLegacyPacedMaxMbps
	// Roundtrip bench counts write+read bytes; windowed QUIC uses independent C2S/S2C credit (~2× one-way ~15 Mbit/s).
	connectUDPLocalizeCeilingMax = 32.0
)

// datagramTransportLink models QUIC wire RTT + in-flight window for CONNECT-UDP localize benches.
type datagramTransportLink interface {
	quicDialOverride() QUICDialFunc
}

type instantDatagramLink struct{}

func (instantDatagramLink) quicDialOverride() QUICDialFunc { return nil }

type windowedDatagramLink struct {
	rtt         time.Duration
	windowBytes int
}

func (w windowedDatagramLink) quicDialOverride() QUICDialFunc {
	return windowedDatagramQUICDial(w.rtt, w.windowBytes)
}

func benchWindowedDatagramLink() windowedDatagramLink {
	return windowedDatagramLink{
		rtt:         localizeBenchRTT,
		windowBytes: localizeBenchWindowBytes,
	}
}

func windowedDatagramQUICDial(rtt time.Duration, windowBytes int) QUICDialFunc {
	if windowBytes <= 0 {
		windowBytes = localizeBenchWindowBytes
	}
	if rtt <= 0 {
		rtt = localizeBenchRTT
	}
	return func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
		remote, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return nil, err
		}
		local, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
		if err != nil {
			return nil, err
		}
		wrapped := newWindowedDatagramConn(local, rtt, windowBytes)
		return quic.Dial(ctx, wrapped, remote, tlsCfg, cfg)
	}
}

type windowedDatagramConn struct {
	inner       net.PacketConn
	rtt         time.Duration
	windowBytes int

	mu          sync.Mutex
	cond        *sync.Cond
	inflightC2S int
	inflightS2C int
	closed      bool
}

func newWindowedDatagramConn(inner net.PacketConn, rtt time.Duration, windowBytes int) *windowedDatagramConn {
	c := &windowedDatagramConn{
		inner:       inner,
		rtt:         rtt,
		windowBytes: windowBytes,
	}
	c.cond = sync.NewCond(&c.mu)
	return c
}

func (c *windowedDatagramConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if len(p) == 0 {
		return c.inner.WriteTo(p, addr)
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

		n, err := c.inner.WriteTo(p[:chunk], addr)
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
	}
	return total, nil
}

func (c *windowedDatagramConn) releaseC2S(n int) {
	c.mu.Lock()
	c.inflightC2S -= n
	if c.inflightC2S < 0 {
		c.inflightC2S = 0
	}
	c.cond.Broadcast()
	c.mu.Unlock()
}

func (c *windowedDatagramConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if len(p) == 0 {
		return c.inner.ReadFrom(p)
	}
	c.mu.Lock()
	for c.inflightS2C >= c.windowBytes && !c.closed {
		c.cond.Wait()
	}
	if c.closed {
		c.mu.Unlock()
		return 0, nil, net.ErrClosed
	}
	avail := c.windowBytes - c.inflightS2C
	c.mu.Unlock()
	if avail > len(p) {
		avail = len(p)
	}

	n, addr, err := c.inner.ReadFrom(p[:avail])
	if n > 0 {
		c.mu.Lock()
		c.inflightS2C += n
		c.mu.Unlock()
		credit := n
		if c.rtt > 0 {
			time.AfterFunc(c.rtt, func() { c.releaseS2C(credit) })
		} else {
			c.releaseS2C(credit)
		}
	}
	return n, addr, err
}

func (c *windowedDatagramConn) releaseS2C(n int) {
	c.mu.Lock()
	c.inflightS2C -= n
	if c.inflightS2C < 0 {
		c.inflightS2C = 0
	}
	c.cond.Broadcast()
	c.mu.Unlock()
}

func (c *windowedDatagramConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.cond.Broadcast()
	c.mu.Unlock()
	return c.inner.Close()
}

func (c *windowedDatagramConn) LocalAddr() net.Addr  { return c.inner.LocalAddr() }
func (c *windowedDatagramConn) SetDeadline(t time.Time) error      { return c.inner.SetDeadline(t) }
func (c *windowedDatagramConn) SetReadDeadline(t time.Time) error  { return c.inner.SetReadDeadline(t) }
func (c *windowedDatagramConn) SetWriteDeadline(t time.Time) error { return c.inner.SetWriteDeadline(t) }

func benchConnectUDPRoundtrip(t *testing.T, link datagramTransportLink, duration time.Duration) (int64, float64, error) {
	t.Helper()
	echo := runUDPEcho(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	echoAddr := echo.LocalAddr().(*net.UDPAddr)

	proxyPort := startInProcessMasqueUDPProxy(t, func(mux *http.ServeMux, proxyPort int) {
		registerMasqueUDPProxyHandler(t, mux, proxyPort)
	})

	waitCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	opts := ClientOptions{
		Server:              "127.0.0.1",
		ServerPort:          uint16(proxyPort),
		MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
	}
	if dial := link.quicDialOverride(); dial != nil {
		opts.QUICDial = dial
	}

	session, err := (CoreClientFactory{}).NewSession(waitCtx, opts)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = session.Close() }()

	pkt, err := session.ListenPacket(waitCtx, M.Socksaddr{
		Addr: netip.MustParseAddr(echoAddr.IP.String()),
		Port: uint16(echoAddr.Port),
	})
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = pkt.Close() }()

	payload := make([]byte, 1200)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	buf := make([]byte, 2048)
	deadline := time.Now().Add(duration)
	var total int64
	for time.Now().Before(deadline) {
		_ = pkt.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if _, err := pkt.WriteTo(payload, echoAddr); err != nil {
			if total > 0 {
				break
			}
			return 0, 0, err
		}
		_ = pkt.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := pkt.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() && total > 0 {
				break
			}
			if total > 0 {
				break
			}
			return 0, 0, err
		}
		total += int64(n) * 2
	}
	secs := duration.Seconds()
	if secs <= 0 {
		secs = 1
	}
	return total, float64(total*8) / secs / 1e6, nil
}

func benchConnectUDPUpload(
	t *testing.T,
	link datagramTransportLink,
	duration time.Duration,
	targetMbit float64,
	payloadLen int,
) (int64, float64, error) {
	t.Helper()
	if payloadLen <= 0 {
		payloadLen = connectudp.DefaultBenchUDPPayloadLen
	}
	sink, _ := runUDPSink(t, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	sinkAddr := sink.LocalAddr().(*net.UDPAddr)

	proxyPort := startInProcessMasqueUDPProxy(t, func(mux *http.ServeMux, proxyPort int) {
		registerMasqueUDPProxyHandler(t, mux, proxyPort)
	})

	waitCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	opts := ClientOptions{
		Server:              "127.0.0.1",
		ServerPort:          uint16(proxyPort),
		MasqueQUICCryptoTLS: &tls.Config{InsecureSkipVerify: true},
	}
	if dial := link.quicDialOverride(); dial != nil {
		opts.QUICDial = dial
	}

	session, err := (CoreClientFactory{}).NewSession(waitCtx, opts)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = session.Close() }()

	pkt, err := session.ListenPacket(waitCtx, M.Socksaddr{
		Addr: netip.MustParseAddr(sinkAddr.IP.String()),
		Port: uint16(sinkAddr.Port),
	})
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = pkt.Close() }()

	payload := make([]byte, payloadLen)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	pace := connectudp.PaceInterval(payloadLen, targetMbit)
	deadline := time.Now().Add(duration)
	var sent int64
	for time.Now().Before(deadline) {
		_ = pkt.SetWriteDeadline(time.Now().Add(2 * time.Second))
		n, err := pkt.WriteTo(payload, sinkAddr)
		if err != nil {
			if sent > 0 {
				break
			}
			return 0, 0, err
		}
		sent += int64(n)
		if pace > 0 {
			time.Sleep(pace)
		}
	}
	secs := duration.Seconds()
	if secs <= 0 {
		secs = 1
	}
	return sent, float64(sent*8) / secs / 1e6, nil
}

// TestConnectUDPLocalizeInstantRoundtrip benches CONNECT-UDP echo on an instant in-process link (localize L1).
func TestConnectUDPLocalizeInstantRoundtrip(t *testing.T) {
	const duration = 400 * time.Millisecond
	bytes, mbps, err := benchConnectUDPRoundtrip(t, instantDatagramLink{}, duration)
	if err != nil {
		t.Fatalf("connect-udp localize L1 roundtrip: %v", err)
	}
	t.Logf("connect-udp localize L1 roundtrip: %.1f Mbit/s (%d bytes)", mbps, bytes)
	if mbps < connectUDPLocalizeFastMbps {
		t.Fatalf("L1 roundtrip slow: %.1f Mbit/s (want >= %.0f)", mbps, connectUDPLocalizeFastMbps)
	}
}

// TestConnectUDPLocalizeWindowedRoundtrip benches CONNECT-UDP echo with bench-shaped QUIC datagram window
// (~64 KiB in flight / 35 ms RTT ≈ 4–28 Mbit/s roundtrip band, same profile as connect-ip/stream L3).
func TestConnectUDPLocalizeWindowedRoundtrip(t *testing.T) {
	const duration = localizeBenchDuration
	bytes, mbps, err := benchConnectUDPRoundtrip(t, benchWindowedDatagramLink(), duration)
	if err != nil {
		t.Fatalf("connect-udp localize L3 roundtrip: %v", err)
	}
	t.Logf("connect-udp localize L3 windowed roundtrip: %.1f Mbit/s (%d bytes)", mbps, bytes)
	if bytes < localizeBenchMinBytes {
		t.Fatalf("L3 roundtrip=%d bytes too small for windowed datagram profiling", bytes)
	}
	if mbps < connectUDPLocalizeCeilingMin || mbps > connectUDPLocalizeCeilingMax {
		t.Fatalf("L3 windowed roundtrip: %.1f Mbit/s (want %.0f–%.0f)", mbps, connectUDPLocalizeCeilingMin, connectUDPLocalizeCeilingMax)
	}
}

// TestConnectUDPLocalizeBurstUpload benches unlimited one-way upload on instant link (docker max-burst path).
func TestConnectUDPLocalizeBurstUpload(t *testing.T) {
	const duration = localizeBenchDuration
	bytes, mbps, err := benchConnectUDPUpload(t, instantDatagramLink{}, duration, 0, connectudp.DefaultBenchUDPPayloadLen)
	if err != nil {
		t.Fatalf("connect-udp localize burst upload: %v", err)
	}
	t.Logf("connect-udp localize burst upload: %.1f Mbit/s (%d bytes)", mbps, bytes)
	if mbps < connectUDPLocalizeBurstMinMbps {
		t.Fatalf("burst upload slow: %.1f Mbit/s (want >= %.0f)", mbps, connectUDPLocalizeBurstMinMbps)
	}
}

// TestConnectUDPLocalizePacedUpload benches docker-aligned paced upload (8 Mbit/s target) on instant link.
// Sender pacing mirrors udp_masque_send.py; in-proc MASQUE stack caps goodput below docker WAN KPI (~6.75).
func TestConnectUDPLocalizePacedUpload(t *testing.T) {
	const duration = localizeBenchDuration
	bytes, mbps, err := benchConnectUDPUpload(
		t,
		instantDatagramLink{},
		duration,
		dockerBenchUDPTargetMbit,
		connectudp.DefaultBenchUDPPayloadLen,
	)
	if err != nil {
		t.Fatalf("connect-udp localize paced upload: %v", err)
	}
	t.Logf("connect-udp localize paced upload: %.1f Mbit/s (%d bytes)", mbps, bytes)
	if bytes < localizeBenchMinBytes/4 {
		t.Fatalf("paced upload=%d bytes too small for profiling", bytes)
	}
	if mbps < connectUDPLocalizePacedMinMbps || mbps > connectUDPLocalizePacedMaxMbps {
		t.Fatalf(
			"paced upload: %.1f Mbit/s (want %.1f–%.1f in-proc band at target %.0f Mbit/s)",
			mbps,
			connectUDPLocalizePacedMinMbps,
			connectUDPLocalizePacedMaxMbps,
			dockerBenchUDPTargetMbit,
		)
	}
}

// TestConnectUDPLocalizeWindowedPacedUpload benches paced upload on windowed QUIC link (64 KiB / 35 ms RTT).
// Goodput is checked against the in-proc band; ExpectedPacedGoodputMbit documents docker WAN calibration.
func TestConnectUDPLocalizeWindowedPacedUpload(t *testing.T) {
	const duration = localizeBenchDuration
	bytes, mbps, err := benchConnectUDPUpload(
		t,
		benchWindowedDatagramLink(),
		duration,
		dockerBenchUDPTargetMbit,
		connectudp.DefaultBenchUDPPayloadLen,
	)
	if err != nil {
		t.Fatalf("connect-udp localize windowed paced upload: %v", err)
	}
	expectedDocker := connectudp.ExpectedPacedGoodputMbit(dockerBenchUDPTargetMbit)
	minDocker := connectudp.MinPacedGoodputMbit(dockerBenchUDPTargetMbit)
	t.Logf(
		"connect-udp localize windowed paced upload: %.1f Mbit/s (%d bytes); docker calibrated %.2f floor %.2f",
		mbps, bytes, expectedDocker, minDocker,
	)
	if bytes < localizeBenchMinBytes/8 {
		t.Fatalf("windowed paced upload=%d bytes too small for profiling", bytes)
	}
	if mbps < connectUDPLocalizePacedMinMbps || mbps > connectUDPLocalizePacedMaxMbps {
		t.Fatalf(
			"windowed paced upload: %.1f Mbit/s (want %.1f–%.1f in-proc band at target %.0f Mbit/s; docker KPI ~%.2f)",
			mbps,
			connectUDPLocalizePacedMinMbps,
			connectUDPLocalizePacedMaxMbps,
			dockerBenchUDPTargetMbit,
			expectedDocker,
		)
	}
}

// TestConnectUDPLocalizeBurstVsPacedContract ensures burst capacity exceeds paced floor on the same harness.
func TestConnectUDPLocalizeBurstVsPacedContract(t *testing.T) {
	t.Parallel()
	if connectUDPLocalizeBurstMinMbps <= connectUDPLocalizePacedMaxMbps {
		t.Fatalf("burst min %.0f must exceed paced max %.0f", connectUDPLocalizeBurstMinMbps, connectUDPLocalizePacedMaxMbps)
	}
	pace := connectudp.PaceInterval(connectudp.DefaultBenchUDPPayloadLen, dockerBenchUDPTargetMbit)
	if pace <= 0 {
		t.Fatal("expected non-zero pace interval for docker target")
	}
	if got := connectudp.PaceInterval(connectudp.DefaultBenchUDPPayloadLen, 0); got != 0 {
		t.Fatalf("burst pace interval = %v want 0", got)
	}
}
