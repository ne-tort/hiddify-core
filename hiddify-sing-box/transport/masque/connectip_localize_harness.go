package masque

// In-process CONNECT-IP localize harness (W-IP-5 IP-TEST-02; W-IP-6 moved to .go for inttest export).

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	fwd "github.com/sagernet/sing-box/transport/masque/forwarder"
	cip "github.com/sagernet/sing-box/transport/masque/connectip"
	M "github.com/sagernet/sing/common/metadata"
)

// connectIPLocalizeVerdict bands (Mbit/s) for in-process upload benches.
const (
	connectIPLocalizeFastMbps   = 80.0 // docker BENCH_CONNECT_IP_MIN_UP_MBIT; in-proc instant L1 floor
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

// forwarderPipeConn adapts IPPacketSession for RunConnectIPTCPPacketPlaneForwarder.
type forwarderPipeConn struct {
	IPPacketSession
	peerPrefixes []netip.Prefix
}

func (c *forwarderPipeConn) CurrentPeerPrefixes() []netip.Prefix { return c.peerPrefixes }

type connectIPUploadHarness struct {
	clientSess  IPPacketSession
	serverConn  *forwarderPipeConn
	clientNS    *cip.Netstack
	waitIngress func()
	fwdCancel   context.CancelFunc
	fwdDone     chan error
	remoteLn    net.Listener
}

// connectIPUploadHarnessOpts configures the harness remote TCP target (forwarder onward dial).
type connectIPUploadHarnessOpts struct {
	remoteEcho         bool
	remoteDownloadFeed bool // default: writer loop (download benches); false = discard accepted conns
	// RemoteConnMode overrides remoteEcho/remoteDownloadFeed per accept ("discard" | "feed").
	RemoteConnMode       func() string
	onRemoteAccept       func()
	WriteQueueMetrics    *fwd.WriteQueueMetrics    // forwarder writeCh (ACK/control segments)
	DownloadQueueMetrics *fwd.DownloadQueueMetrics // forwarder downloadCh (remote→client DATA)
	IngressWakeFlushes   *atomic.Int32
	EgressWakeFlushes    *atomic.Int32
}

func startConnectIPUploadHarness(t *testing.T, link packetLink, opts ...connectIPUploadHarnessOpts) *connectIPUploadHarness {
	t.Helper()
	var o connectIPUploadHarnessOpts
	if len(opts) > 0 {
		o = opts[0]
	}
	clientSess, serverSess := link.endpoints()
	peer := netip.MustParsePrefix("198.18.0.2/32")

	clientNS, err := cip.NewNetstackForSession(context.Background(), clientSess, connectIPHarnessNetstackOpts(o))
	if err != nil {
		t.Fatalf("client netstack: %v", err)
	}

	ln := startConnectIPRemoteListener(t, o)

	serverConn := &forwarderPipeConn{
		IPPacketSession: serverSess,
		peerPrefixes:    []netip.Prefix{peer},
	}
	fwdCtx, fwdCancel := context.WithCancel(context.Background())
	fwdDone := make(chan error, 1)
	go func() {
		fwdOpts := fwd.ConnectIPTCPForwarderOptions{
			AllowPrivateTargets:   true,
			LeaveConnOpenOnCancel: true,
		}
		if o.WriteQueueMetrics != nil {
			fwdOpts.WriteQueueMetrics = o.WriteQueueMetrics
		}
		if o.DownloadQueueMetrics != nil {
			fwdOpts.DownloadQueueMetrics = o.DownloadQueueMetrics
		}
		fwdDone <- fwd.RunConnectIPTCPPacketPlaneForwarder(fwdCtx, serverConn, fwdOpts)
	}()

	waitIngress := startConnectIPIngressRelay(clientSess, clientNS, o.IngressWakeFlushes)

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
	if h.fwdDone != nil {
		select {
		case <-h.fwdDone:
		default:
			select {
			case <-h.fwdDone:
			case <-time.After(2 * time.Second):
			}
		}
	}
}

// restartForwarder stops and relaunches RunConnectIPTCPPacketPlaneForwarder on the same packet session.
// Mirrors docker compose restart masque-server-core for in-proc pipe localize.
func (h *connectIPUploadHarness) restartForwarder(t *testing.T) error {
	t.Helper()
	if h.fwdCancel == nil || h.serverConn == nil {
		return fmt.Errorf("forwarder not running")
	}
	h.fwdCancel()
	select {
	case err := <-h.fwdDone:
		if err != nil && err != context.Canceled {
			t.Logf("forwarder exit on restart: %v", err)
		}
	case <-time.After(3 * time.Second):
		return fmt.Errorf("forwarder did not exit within 3s")
	}
	fwdCtx, fwdCancel := context.WithCancel(context.Background())
	fwdDone := make(chan error, 1)
	go func() {
		fwdDone <- fwd.RunConnectIPTCPPacketPlaneForwarder(fwdCtx, h.serverConn, fwd.ConnectIPTCPForwarderOptions{
			AllowPrivateTargets:   true,
			LeaveConnOpenOnCancel: true,
		})
	}()
	h.fwdCancel = fwdCancel
	h.fwdDone = fwdDone
	return nil
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

func benchConnectIPUploadLayerBest(t *testing.T, name string, link packetLink, duration time.Duration, attempts int) connectIPUploadBenchResult {
	t.Helper()
	if attempts < 1 {
		attempts = 1
	}
	var best connectIPUploadBenchResult
	for i := 0; i < attempts; i++ {
		r := benchConnectIPUploadLayer(t, name, link, duration)
		if r.err != nil {
			return r
		}
		if i == 0 || r.mbps > best.mbps {
			best = r
		}
	}
	return best
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

// connectIPUploadNativeLayerHint localizes upload gap after pipe L1 (no QUIC) vs native H3 C2S.
func connectIPUploadNativeLayerHint(pipeL1Mbps, nativeMbps float64) string {
	if pipeL1Mbps <= 0 {
		return "inconclusive: pipe L1 Mbps missing"
	}
	ratio := nativeMbps / pipeL1Mbps
	switch {
	case pipeL1Mbps < connectIPLocalizeFastMbps:
		return "bottleneck: forwarder/netstack (pipe L1 below regression floor)"
	case ratio < connectIPSynthPipeMinRatio:
		return fmt.Sprintf("bottleneck: QUIC/datagram C2S egress (native/pipe=%.2f < %.2f)", ratio, connectIPSynthPipeMinRatio)
	case nativeMbps < connectIPSynthProdMinMbps:
		return "pipe+QUIC regression OK; DoD gap likely TUN/container or platform ceiling — Docker only after this gate PASS"
	default:
		return "all in-proc layers at DoD — run Docker connect-ip-h3-tun @0ms"
	}
}

func startConnectIPDownloadHarness(t *testing.T, link packetLink, opts ...connectIPUploadHarnessOpts) *connectIPUploadHarness {
	t.Helper()
	var o connectIPUploadHarnessOpts
	if len(opts) > 0 {
		o = opts[0]
	}
	o.remoteDownloadFeed = true
	clientSess, serverSess := link.endpoints()
	return startConnectIPLocalizePipeHarness(t, clientSess, serverSess, o)
}

func egressBatchWakeHook(calls *atomic.Int32) func() {
	if calls == nil {
		return nil
	}
	return func() { calls.Add(1) }
}

func startConnectIPRemoteListener(t *testing.T, o connectIPUploadHarnessOpts) net.Listener {
	t.Helper()
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
			if o.onRemoteAccept != nil {
				o.onRemoteAccept()
			}
			go func(c net.Conn) {
				defer c.Close()
				mode := "discard"
				if o.RemoteConnMode != nil {
					mode = o.RemoteConnMode()
				} else if o.remoteDownloadFeed {
					mode = "feed"
				} else if o.remoteEcho {
					mode = "echo"
				}
				switch mode {
				case "iperf_reverse":
					// iperf3 -R setup: read client params (~89B), reply header (~53B), then bulk.
					hdr := make([]byte, 128)
					if _, err := io.ReadFull(c, hdr[:89]); err != nil {
						return
					}
					reply := make([]byte, 53)
					reply[0] = 0x49 // 'I' — visible marker in synth
					if _, err := c.Write(reply); err != nil {
						return
					}
					deadline := time.Now().Add(30 * time.Second)
					for time.Now().Before(deadline) {
						if _, err := c.Write(buf); err != nil {
							return
						}
					}
				case "feed":
					deadline := time.Now().Add(30 * time.Second)
					for time.Now().Before(deadline) {
						if _, err := c.Write(buf); err != nil {
							return
						}
					}
				case "echo":
					_, _ = io.Copy(c, c)
				default:
					_, _ = io.Copy(io.Discard, c)
				}
			}(c)
		}
	}()
	return ln
}

func connectIPHarnessNetstackOpts(o connectIPUploadHarnessOpts) cip.NetstackOptions {
	return cip.NetstackOptions{
		LocalIPv4:              netip.MustParseAddr("198.18.0.2"),
		LocalIPv6:              netip.MustParseAddr("fd00::2"),
		MTU:                    cip.H3NetstackMTU(cip.DefaultDatagramCeilingMax),
		OnEgressBatchComplete:  egressBatchWakeHook(o.EgressWakeFlushes),
	}
}

func startConnectIPLocalizePipeHarness(t *testing.T, clientSess, serverSess IPPacketSession, opts ...connectIPUploadHarnessOpts) *connectIPUploadHarness {
	t.Helper()
	var o connectIPUploadHarnessOpts
	if len(opts) > 0 {
		o = opts[0]
	}
	peer := netip.MustParsePrefix("198.18.0.2/32")
	clientNS, err := cip.NewNetstackForSession(context.Background(), clientSess, connectIPHarnessNetstackOpts(o))
	if err != nil {
		t.Fatalf("client netstack: %v", err)
	}
	if o.RemoteConnMode == nil {
		o.remoteDownloadFeed = true
	}
	ln := startConnectIPRemoteListener(t, o)
	serverConn := &forwarderPipeConn{IPPacketSession: serverSess, peerPrefixes: []netip.Prefix{peer}}
	fwdCtx, fwdCancel := context.WithCancel(context.Background())
	fwdDone := make(chan error, 1)
	go func() {
		fwdOpts := fwd.ConnectIPTCPForwarderOptions{
			AllowPrivateTargets:   true,
			LeaveConnOpenOnCancel: true,
		}
		if o.WriteQueueMetrics != nil {
			fwdOpts.WriteQueueMetrics = o.WriteQueueMetrics
		}
		if o.DownloadQueueMetrics != nil {
			fwdOpts.DownloadQueueMetrics = o.DownloadQueueMetrics
		}
		fwdDone <- fwd.RunConnectIPTCPPacketPlaneForwarder(fwdCtx, serverConn, fwdOpts)
	}()
	return &connectIPUploadHarness{
		clientSess: clientSess, serverConn: serverConn, clientNS: clientNS,
		waitIngress: startConnectIPIngressRelay(clientSess, clientNS, o.IngressWakeFlushes),
		fwdCancel: fwdCancel, fwdDone: fwdDone, remoteLn: ln,
	}
}

func benchConnectIPDownloadLayer(t *testing.T, layer string, link packetLink, duration time.Duration) connectIPUploadBenchResult {
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
			buf := make([]byte, 256*1024)
			deadline := time.Now().Add(30 * time.Second)
			for time.Now().Before(deadline) {
				if _, err := c.Write(buf); err != nil {
					return
				}
			}
		}()
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			return connectIPUploadBenchResult{layer: layer, err: err}
		}
		defer conn.Close()
		n, mbps, err := measureTCPDownloadMbps(conn, duration)
		return connectIPUploadBenchResult{layer: layer, mbps: mbps, bytes: n, err: err}
	}

	h := startConnectIPDownloadHarness(t, link)
	defer h.close()
	conn := h.dialRemote(t)
	defer conn.Close()
	n, mbps, err := measureTCPDownloadMbps(conn, duration)
	return connectIPUploadBenchResult{layer: layer, mbps: mbps, bytes: n, err: err}
}

func verdictConnectIPDownload(l0, l1, l3 connectIPUploadBenchResult) string {
	switch {
	case !l0.ok() || !l1.ok() || !l3.ok():
		return "FAIL: bench error"
	case l1.mbps >= connectIPLocalizeFastMbps && l3.mbps >= connectIPLocalizeCeilingMin && l3.mbps <= connectIPLocalizeCeilingMax:
		return "masque connect-ip packet plane: L1 fast download, L3 windowed ~64KiB/RTT band → S2C DATA window + client ACK credit (not per-segment RTT sleep)"
	case l1.mbps < connectIPLocalizeFastMbps && l0.mbps >= connectIPLocalizeFastMbps:
		return "masque connect-ip: L0 fast, L1 download slow → forwarder pumpRemoteToClient or client ingress (not wire RTT)"
	case l1.mbps >= connectIPLocalizeFastMbps && l3.mbps > connectIPLocalizeCeilingMax:
		return "L3 window model did not reproduce download ceiling (harness calibration)"
	default:
		return "inconclusive: review download layer Mbps"
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

type clientPacketSessionLink struct {
	inner packetLink
}

func (l clientPacketSessionLink) endpoints() (IPPacketSession, IPPacketSession) {
	rawClient, server := l.inner.endpoints()
	return cip.NewClientPacketSessionPipeShim(rawClient), server
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

const connectIPEgressDrainTimeout = 2 * time.Second

func flushConnectIPEgressAfterClose(h *connectIPUploadHarness) {
	waitConnectIPEgressDrained(nil, h)
}

// waitConnectIPEgressDrained spins outbound drain until the client queue is empty.
// When tb is non-nil, failure to drain within connectIPEgressDrainTimeout fails the test.
func waitConnectIPEgressDrained(tb testing.TB, h *connectIPUploadHarness) {
	if h == nil || h.clientNS == nil {
		return
	}
	deadline := time.Now().Add(connectIPEgressDrainTimeout)
	for time.Now().Before(deadline) {
		h.clientNS.ScheduleOutboundDrain()
		if h.clientNS.OutboundQueueDepth() == 0 {
			if err := h.clientNS.TerminalError(); err != nil && tb != nil {
				tb.Helper()
				tb.Fatalf("unexpected terminal netstack error after egress drain: %v", err)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	if tb != nil {
		tb.Helper()
		tb.Fatalf("outbound queue not drained after %v (depth=%d)", connectIPEgressDrainTimeout, h.clientNS.OutboundQueueDepth())
	}
}
