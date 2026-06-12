package masque

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	fwd "github.com/sagernet/sing-box/transport/masque/forwarder"
	M "github.com/sagernet/sing/common/metadata"
)

// connectIPLocalizeVerdict bands (Mbit/s) for in-process upload benches.
const (
	connectIPLocalizeFastMbps   = 80.0
	connectIPLocalizeCeilingMax = 28.0
	connectIPLocalizeCeilingMin = 4.0
)

type connectIPUploadBenchResult struct {
	layer string
	mbps  float64
	bytes int64
	err   error
}

func (r connectIPUploadBenchResult) ok() bool { return r.err == nil }

func measureTCPDownloadMbps(conn net.Conn, duration time.Duration) (int64, float64, error) {
	deadline := time.Now().Add(duration)
	buf := make([]byte, 256*1024)
	var total int64
	for time.Now().Before(deadline) {
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Read(buf)
		if n > 0 {
			total += int64(n)
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() && total > 0 {
				break
			}
			if err == io.EOF {
				break
			}
			if total > 0 {
				break
			}
			return 0, 0, err
		}
	}
	secs := duration.Seconds()
	if secs <= 0 {
		secs = 1
	}
	return total, float64(total*8) / secs / 1e6, nil
}

func measureTCPUploadMbps(conn net.Conn, duration time.Duration) (int64, float64, error) {
	deadline := time.Now().Add(duration)
	buf := make([]byte, 256*1024)
	var total int64
	for time.Now().Before(deadline) {
		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Write(buf)
		if n > 0 {
			total += int64(n)
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() && total > 0 {
				break
			}
			if err == io.EOF {
				break
			}
			if total > 0 {
				break
			}
			return 0, 0, err
		}
	}
	secs := duration.Seconds()
	if secs <= 0 {
		secs = 1
	}
	mbps := float64(total*8) / secs / 1e6
	return total, mbps, nil
}

// forwarderPipeConn adapts IPPacketSession for RunConnectIPTCPPacketPlaneForwarder.
type forwarderPipeConn struct {
	IPPacketSession
	peerPrefixes []netip.Prefix
}

func (c *forwarderPipeConn) CurrentPeerPrefixes() []netip.Prefix { return c.peerPrefixes }

type connectIPUploadHarness struct {
	clientSess IPPacketSession
	serverConn *forwarderPipeConn
	clientNS   *connectIPTCPNetstack
	waitIngress func()
	fwdCancel  context.CancelFunc
	fwdDone    chan error
	remoteLn   net.Listener
}

// connectIPUploadHarnessOpts configures the harness remote TCP target (forwarder onward dial).
type connectIPUploadHarnessOpts struct {
	remoteEcho     bool
	onRemoteAccept func()
	WriteQueueMetrics *fwd.WriteQueueMetrics
}

func startConnectIPUploadHarness(t *testing.T, link packetLink, opts ...connectIPUploadHarnessOpts) *connectIPUploadHarness {
	t.Helper()
	var o connectIPUploadHarnessOpts
	if len(opts) > 0 {
		o = opts[0]
	}
	clientSess, serverSess := link.endpoints()
	peer := netip.MustParsePrefix("198.18.0.2/32")

	clientNS, err := newConnectIPTCPNetstack(context.Background(), clientSess, connectIPTCPNetstackOptions{
		LocalIPv4: netip.MustParseAddr("198.18.0.2"),
		LocalIPv6: netip.MustParseAddr("fd00::2"),
		MTU:       1372,
	})
	if err != nil {
		t.Fatalf("client netstack: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("remote listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if o.onRemoteAccept != nil {
				o.onRemoteAccept()
			}
			go func(c net.Conn) {
				defer c.Close()
				if o.remoteEcho {
					_, _ = io.Copy(c, c)
				} else {
					_, _ = io.Copy(io.Discard, c)
				}
			}(c)
		}
	}()

	serverConn := &forwarderPipeConn{
		IPPacketSession: serverSess,
		peerPrefixes:    []netip.Prefix{peer},
	}
	fwdCtx, fwdCancel := context.WithCancel(context.Background())
	fwdDone := make(chan error, 1)
	go func() {
		fwdOpts := ConnectIPTCPForwarderOptions{AllowPrivateTargets: true}
		if o.WriteQueueMetrics != nil {
			fwdOpts.WriteQueueMetrics = o.WriteQueueMetrics
		}
		fwdDone <- RunConnectIPTCPPacketPlaneForwarder(fwdCtx, serverConn, fwdOpts)
	}()

	waitIngress := runIngressRelay(clientSess, clientNS)

	return &connectIPUploadHarness{
		clientSess:  clientSess,
		serverConn:  serverConn,
		clientNS:    clientNS,
		waitIngress: waitIngress,
		fwdCancel:   fwdCancel,
		fwdDone:     fwdDone,
		remoteLn:    ln,
	}
}

func (h *connectIPUploadHarness) close() {
	if h.fwdCancel != nil {
		h.fwdCancel()
	}
	if h.clientNS != nil {
		_ = h.clientNS.Close()
	}
	if h.clientSess != nil {
		_ = h.clientSess.Close()
	}
	if h.serverConn != nil && h.serverConn.IPPacketSession != nil {
		_ = h.serverConn.IPPacketSession.Close()
	}
	if h.waitIngress != nil {
		h.waitIngress()
	}
	if h.remoteLn != nil {
		_ = h.remoteLn.Close()
	}
	select {
	case <-h.fwdDone:
	default:
		select {
		case <-h.fwdDone:
		case <-time.After(2 * time.Second):
		}
	}
}

func (h *connectIPUploadHarness) dialRemote(t *testing.T) net.Conn {
	t.Helper()
	_, portStr, _ := net.SplitHostPort(h.remoteLn.Addr().String())
	p64, _ := strconv.ParseUint(portStr, 10, 16)
	port := uint16(p64)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	conn, err := h.clientNS.DialContext(ctx, M.ParseSocksaddrHostPort("127.0.0.1", port))
	if err != nil {
		t.Fatalf("dial over connect-ip: %v", err)
	}
	return conn
}

func benchConnectIPUploadLayer(t *testing.T, layer string, link packetLink, duration time.Duration) connectIPUploadBenchResult {
	t.Helper()
	if layer == "L0" {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return connectIPUploadBenchResult{layer: layer, err: err}
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
			return connectIPUploadBenchResult{layer: layer, err: err}
		}
		defer conn.Close()
		n, mbps, err := measureTCPUploadMbps(conn, duration)
		return connectIPUploadBenchResult{layer: layer, mbps: mbps, bytes: n, err: err}
	}

	h := startConnectIPUploadHarness(t, link)
	defer h.close()
	conn := h.dialRemote(t)
	defer conn.Close()
	n, mbps, err := measureTCPUploadMbps(conn, duration)
	return connectIPUploadBenchResult{layer: layer, mbps: mbps, bytes: n, err: err}
}

func verdictConnectIPUpload(l0, l1, l3 connectIPUploadBenchResult) string {
	switch {
	case !l0.ok() || !l1.ok() || !l3.ok():
		return "FAIL: bench error"
	case l1.mbps >= connectIPLocalizeFastMbps && l3.mbps >= connectIPLocalizeCeilingMin && l3.mbps <= connectIPLocalizeCeilingMax:
		return "masque connect-ip packet plane: L1 fast, L3 windowed ~64KiB/RTT band → RTT/credit on link or TCP ACK path (forwarder writeRaw / client WriteNotify)"
	case l1.mbps < connectIPLocalizeFastMbps && l0.mbps >= connectIPLocalizeFastMbps:
		return "masque connect-ip: L0 fast, L1 slow → forwarder or netstack WriteNotify/ingress (not wire RTT)"
	case l1.mbps >= connectIPLocalizeFastMbps && l3.mbps > connectIPLocalizeCeilingMax:
		return "L3 window model did not reproduce ceiling (harness calibration)"
	default:
		return "inconclusive: review layer Mbps"
	}
}

// TestMasqueConnectIPLocalizeBottleneck localizes connect-ip TUN upload (~15 Mbit/s field).
func TestMasqueConnectIPLocalizeBottleneck(t *testing.T) {
	const duration = 400 * time.Millisecond

	l0 := benchConnectIPUploadLayer(t, "L0", nil, duration)
	l1 := benchConnectIPUploadLayer(t, "L1", instantPacketLink{}, duration)
	l2 := benchConnectIPUploadLayer(t, "L2", windowedPacketLink{
		rtt:         35 * time.Millisecond,
		windowBytes: 16 << 20,
	}, duration)
	l3 := benchConnectIPUploadLayer(t, "L3", windowedPacketLink{
		rtt:         35 * time.Millisecond,
		windowBytes: 64 * 1024,
	}, duration)
	l256 := benchConnectIPUploadLayer(t, "L256", windowedPacketLink{
		rtt:         35 * time.Millisecond,
		windowBytes: 256 * 1024,
	}, duration)

	for _, r := range []connectIPUploadBenchResult{l0, l1, l2, l3, l256} {
		if r.err != nil {
			t.Fatalf("%s: %v", r.layer, r.err)
		}
		t.Logf("connect-ip localize %s: %.1f Mbit/s (%d bytes)", r.layer, r.mbps, r.bytes)
	}

	v := verdictConnectIPUpload(l0, l1, l3)
	t.Logf("connect-ip localize verdict: %s", v)
}

func startConnectIPDownloadHarness(t *testing.T, link packetLink) *connectIPUploadHarness {
	t.Helper()
	clientSess, serverSess := link.endpoints()
	return startConnectIPLocalizePipeHarness(t, clientSess, serverSess)
}

func startConnectIPLocalizePipeHarness(t *testing.T, clientSess, serverSess IPPacketSession) *connectIPUploadHarness {
	t.Helper()
	peer := netip.MustParsePrefix("198.18.0.2/32")
	clientNS, err := newConnectIPTCPNetstack(context.Background(), clientSess, connectIPTCPNetstackOptions{
		LocalIPv4: netip.MustParseAddr("198.18.0.2"),
		LocalIPv6: netip.MustParseAddr("fd00::2"),
		MTU:       1372,
	})
	if err != nil {
		t.Fatalf("client netstack: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("remote listen: %v", err)
	}
	go func() {
		buf := make([]byte, 256*1024)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				deadline := time.Now().Add(30 * time.Second)
				for time.Now().Before(deadline) {
					if _, err := c.Write(buf); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	serverConn := &forwarderPipeConn{IPPacketSession: serverSess, peerPrefixes: []netip.Prefix{peer}}
	fwdCtx, fwdCancel := context.WithCancel(context.Background())
	fwdDone := make(chan error, 1)
	go func() {
		fwdDone <- RunConnectIPTCPPacketPlaneForwarder(fwdCtx, serverConn, ConnectIPTCPForwarderOptions{
			AllowPrivateTargets: true,
		})
	}()
	return &connectIPUploadHarness{
		clientSess: clientSess, serverConn: serverConn, clientNS: clientNS,
		waitIngress: runIngressRelay(clientSess, clientNS),
		fwdCancel: fwdCancel, fwdDone: fwdDone, remoteLn: ln,
	}
}

func TestMasqueConnectIPLocalizeDownload(t *testing.T) {
	const duration = 400 * time.Millisecond
	h := startConnectIPDownloadHarness(t, instantPacketLink{})
	defer h.close()
	conn := h.dialRemote(t)
	defer conn.Close()
	n, mbps, err := measureTCPDownloadMbps(conn, duration)
	if err != nil {
		t.Fatalf("download bench: %v", err)
	}
	t.Logf("connect-ip download L1: %.1f Mbit/s (%d bytes)", mbps, n)
	if mbps < connectIPLocalizeFastMbps {
		t.Fatalf("download L1 slow: %.1f Mbit/s (want >= %.0f)", mbps, connectIPLocalizeFastMbps)
	}
}

// benignOnceWriteSession injects one remote QUIC NO_ERROR (0x100) on the next WritePacket
// after ArmTeardown0x100 — models H3 half-close during CONNECT-IP egress drain.
type benignOnceWriteSession struct {
	inner IPPacketSession
	armed atomic.Bool
	fired atomic.Bool
}

func (s *benignOnceWriteSession) ArmTeardown0x100() {
	s.armed.Store(true)
}

func (s *benignOnceWriteSession) ReadPacket(buffer []byte) (int, error) {
	return s.inner.ReadPacket(buffer)
}

func (s *benignOnceWriteSession) WritePacket(buffer []byte) ([]byte, error) {
	if s.armed.Load() && !s.fired.Load() {
		s.fired.Store(true)
		return nil, &quic.ApplicationError{ErrorCode: 0x100, Remote: true}
	}
	return s.inner.WritePacket(buffer)
}

func (s *benignOnceWriteSession) Close() error {
	return s.inner.Close()
}

// waitConnectIPRecycleReady blocks until upload teardown injects benign 0x100 and egress drains.
func waitConnectIPRecycleReady(t *testing.T, h *connectIPUploadHarness, fired *atomic.Bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		h.clientNS.ScheduleOutboundDrain()
		if fired != nil && fired.Load() && h.clientNS.OutboundQueueDepth() == 0 {
			if err := h.clientNS.TerminalError(); err != nil {
				t.Fatalf("unexpected terminal netstack error before recycle dial: %v", err)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	if fired != nil && !fired.Load() {
		t.Fatal("expected one benign 0x100 during upload teardown drain")
	}
	if depth := h.clientNS.OutboundQueueDepth(); depth != 0 {
		t.Fatalf("outbound queue not drained after recycle (depth=%d)", depth)
	}
	if err := h.clientNS.TerminalError(); err != nil {
		t.Fatalf("unexpected terminal netstack error before recycle dial: %v", err)
	}
}

func flushConnectIPEgressAfterClose(h *connectIPUploadHarness) {
	if h == nil || h.clientNS == nil {
		return
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		h.clientNS.ScheduleOutboundDrain()
		if h.clientNS.OutboundQueueDepth() == 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestMasqueConnectIPLocalizeRecycle verifies bulk upload teardown (incl. benign 0x100)
// does not poison the packet plane before a fresh download flow.
func TestMasqueConnectIPLocalizeRecycle(t *testing.T) {
	const uploadDur = 300 * time.Millisecond
	const downloadDur = 400 * time.Millisecond

	rawClient, serverSess := instantPacketLink{}.endpoints()
	clientSess := &benignOnceWriteSession{inner: rawClient}
	h := startConnectIPLocalizePipeHarness(t, clientSess, serverSess)
	defer h.close()

	upConn := h.dialRemote(t)
	upBytes, upMbps, err := measureTCPUploadMbps(upConn, uploadDur)
	if err != nil {
		t.Fatalf("upload bench: %v", err)
	}
	clientSess.ArmTeardown0x100()
	if err := upConn.Close(); err != nil {
		t.Fatalf("close upload conn: %v", err)
	}
	flushConnectIPEgressAfterClose(h)
	waitConnectIPRecycleReady(t, h, &clientSess.fired)

	downConn := h.dialRemote(t)
	defer downConn.Close()
	downBytes, downMbps, err := measureTCPDownloadMbps(downConn, downloadDur)
	if err != nil {
		t.Fatalf("download bench after recycle: %v", err)
	}
	t.Logf("connect-ip recycle upload: %.1f Mbit/s (%d bytes)", upMbps, upBytes)
	t.Logf("connect-ip recycle download: %.1f Mbit/s (%d bytes)", downMbps, downBytes)
	if downMbps < connectIPLocalizeFastMbps {
		t.Fatalf("download after upload recycle slow: %.1f Mbit/s (want >= %.0f)", downMbps, connectIPLocalizeFastMbps)
	}
}

// --- packet link models ---

type packetLink interface {
	endpoints() (IPPacketSession, IPPacketSession)
}

type instantPacketLink struct{}

func (instantPacketLink) endpoints() (IPPacketSession, IPPacketSession) {
	a, b := newPacketPipePair()
	return a, b
}

// windowedPacketLink limits client→server bytes in flight and adds RTT per packet
// (bench-shaped ~64 KiB / RTT ≈ 13–15 Mbit/s at 35 ms).
type windowedPacketLink struct {
	rtt         time.Duration
	windowBytes int
}

func (w windowedPacketLink) endpoints() (IPPacketSession, IPPacketSession) {
	return newWindowedPacketPair(w.rtt, w.windowBytes)
}

func newWindowedPacketPair(rtt time.Duration, windowBytes int) (IPPacketSession, IPPacketSession) {
	if windowBytes <= 0 {
		windowBytes = 64 * 1024
	}
	if rtt <= 0 {
		rtt = 35 * time.Millisecond
	}
	bridge := &windowedPacketBridge{
		rtt:         rtt,
		windowBytes: windowBytes,
		clientRx:    make(chan []byte, 256),
		serverRx:    make(chan []byte, 256),
	}
	bridge.cond = sync.NewCond(&bridge.mu)
	client := &bridgePacketSession{bridge: bridge, role: bridgeRoleClient, done: make(chan struct{})}
	server := &bridgePacketSession{bridge: bridge, role: bridgeRoleServer, done: make(chan struct{})}
	return client, server
}

// bridgePacketSession implements IPPacketSession with RTT + in-flight window.
type bridgePacketSession struct {
	bridge *windowedPacketBridge
	role   bridgeRole
	once   sync.Once
	done   chan struct{}
}

func (s *bridgePacketSession) ReadPacket(buffer []byte) (int, error) {
	rx := s.bridge.clientRx
	if s.role == bridgeRoleServer {
		rx = s.bridge.serverRx
	}
	select {
	case <-s.done:
		return 0, net.ErrClosed
	case pkt, ok := <-rx:
		if !ok {
			return 0, io.EOF
		}
		if len(pkt) > len(buffer) {
			return 0, io.ErrShortBuffer
		}
		return copy(buffer, pkt), nil
	}
}

func (s *bridgePacketSession) WritePacket(buffer []byte) ([]byte, error) {
	if err := s.bridge.write(s.role, buffer); err != nil {
		return nil, err
	}
	return nil, nil
}

func (s *bridgePacketSession) Close() error {
	s.once.Do(func() {
		close(s.done)
		s.bridge.closeBridge()
	})
	return nil
}

type bridgeRole int

const (
	bridgeRoleClient bridgeRole = iota
	bridgeRoleServer
)

type windowedPacketBridge struct {
	mu             sync.Mutex
	cond           *sync.Cond
	rtt            time.Duration
	windowBytes    int
	inflightC2S    int
	pendingRelease int
	releaseTimer   *time.Timer
	clientRx       chan []byte
	serverRx       chan []byte
	closed         bool
}

func (b *windowedPacketBridge) write(role bridgeRole, pkt []byte) error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return net.ErrClosed
	}
	if role == bridgeRoleClient {
		for b.inflightC2S+len(pkt) > b.windowBytes && !b.closed {
			b.cond.Wait()
		}
		if b.closed {
			b.mu.Unlock()
			return net.ErrClosed
		}
		b.inflightC2S += len(pkt)
	}
	b.mu.Unlock()

	dst := b.serverRx
	if role == bridgeRoleServer {
		dst = b.clientRx
	}
	p := append([]byte(nil), pkt...)
	if role == bridgeRoleServer {
		// Model TCP ACK clock: data may reach the forwarder immediately; credit returns after RTT.
		if b.rtt > 0 {
			time.Sleep(b.rtt)
		}
		credit := connectIPLocalizeAckCredit(pkt)
		select {
		case dst <- p:
			b.releaseC2S(credit)
			return nil
		default:
			b.releaseC2S(credit)
			return io.ErrShortBuffer
		}
	}
	select {
	case dst <- p:
		return nil
	default:
		return io.ErrShortBuffer
	}
}

// connectIPLocalizeAckCredit estimates TCP window credit returned by one server→client segment.
func connectIPLocalizeAckCredit(pkt []byte) int {
	const defaultMSS = 1300
	if len(pkt) < 20 || pkt[0]>>4 != 4 || pkt[9] != 6 {
		return defaultMSS
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl+12 > len(pkt) {
		return defaultMSS
	}
	doff := int(pkt[ihl+12]>>4) * 4
	if doff < 20 || ihl+doff > len(pkt) {
		return defaultMSS
	}
	payload := len(pkt) - ihl - doff
	if payload > 0 {
		return payload
	}
	return defaultMSS
}

func (b *windowedPacketBridge) scheduleRelease(credit int) {
	if credit <= 0 {
		return
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.pendingRelease += credit
	if b.releaseTimer == nil && b.rtt > 0 {
		b.releaseTimer = time.AfterFunc(b.rtt, b.flushRelease)
	} else if b.releaseTimer == nil {
		b.flushReleaseLocked()
	}
	b.mu.Unlock()
}

func (b *windowedPacketBridge) flushRelease() {
	b.mu.Lock()
	b.flushReleaseLocked()
	b.mu.Unlock()
}

func (b *windowedPacketBridge) flushReleaseLocked() {
	if b.releaseTimer != nil {
		b.releaseTimer.Stop()
		b.releaseTimer = nil
	}
	credit := b.pendingRelease
	b.pendingRelease = 0
	if credit > 0 {
		b.inflightC2S -= credit
		if b.inflightC2S < 0 {
			b.inflightC2S = 0
		}
		b.cond.Broadcast()
	}
}

func (b *windowedPacketBridge) releaseC2S(n int) {
	b.mu.Lock()
	b.inflightC2S -= n
	if b.inflightC2S < 0 {
		b.inflightC2S = 0
	}
	b.cond.Broadcast()
	b.mu.Unlock()
}

func (b *windowedPacketBridge) closeBridge() {
	b.mu.Lock()
	b.closed = true
	b.flushReleaseLocked()
	b.cond.Broadcast()
	b.mu.Unlock()
}
