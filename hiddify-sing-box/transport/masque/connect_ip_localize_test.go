package masque

import (
	"context"
	"errors"
	"fmt"
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
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	M "github.com/sagernet/sing/common/metadata"
)

// connectIPLocalizeVerdict bands (Mbit/s) for in-process upload benches.
const (
	connectIPLocalizeFastMbps     = 80.0 // docker BENCH_CONNECT_IP_MIN_UP_MBIT; in-proc instant L1 floor
	connectIPLocalizeCeilingMax   = 28.0
	connectIPLocalizeCeilingMin   = 4.0
)

type connectIPUploadBenchResult struct {
	layer string
	mbps  float64
	bytes int64
	err   error
}

func (r connectIPUploadBenchResult) ok() bool { return r.err == nil }

// measureTCPDownloadMbps drains via conn.Read (legacy anti-pattern for CONNECT-stream KPI:
// skips downloadActive / framer boost — use measureTCPDownloadWriteToMbps for synth gates).
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

var errBenchDuration = errors.New("masque: bench duration elapsed")

type benchWriteToSink struct {
	deadline time.Time
	total    int64
}

func (s *benchWriteToSink) Write(p []byte) (int, error) {
	if time.Now().After(s.deadline) {
		return 0, errBenchDuration
	}
	s.total += int64(len(p))
	return len(p), nil
}

// measureTCPDownloadCopyMbps drains conn via io.Copy (route connectionCopy writer_to:
// io.Copy invokes source.WriteTo when present — not conn.Read).
func measureTCPDownloadCopyMbps(conn net.Conn, duration time.Duration) (int64, float64, error) {
	deadline := time.Now().Add(duration)
	_ = conn.SetReadDeadline(deadline)
	defer conn.SetReadDeadline(time.Time{})
	sink := &benchWriteToSink{deadline: deadline}
	_, err := io.Copy(sink, conn)
	if err != nil && err != errBenchDuration && err != io.EOF {
		if sink.total == 0 {
			return 0, 0, err
		}
	}
	secs := duration.Seconds()
	if secs <= 0 {
		secs = 1
	}
	return sink.total, float64(sink.total*8) / secs / 1e6, nil
}

// measureTCPDownloadWriteToMbps drains conn via io.WriterTo (prod route writer_to path).
func measureTCPDownloadWriteToMbps(conn net.Conn, duration time.Duration) (int64, float64, error) {
	wt, ok := conn.(io.WriterTo)
	if !ok {
		return 0, 0, fmt.Errorf("masque: conn lacks io.WriterTo (prod download path)")
	}
	deadline := time.Now().Add(duration)
	_ = conn.SetReadDeadline(deadline)
	defer conn.SetReadDeadline(time.Time{})
	sink := &benchWriteToSink{deadline: deadline}
	_, err := wt.WriteTo(sink)
	if err != nil && err != errBenchDuration && err != io.EOF {
		if sink.total == 0 {
			return 0, 0, err
		}
	}
	secs := duration.Seconds()
	if secs <= 0 {
		secs = 1
	}
	return sink.total, float64(sink.total*8) / secs / 1e6, nil
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
	remoteEcho         bool
	remoteDownloadFeed bool // default: writer loop (download benches); false = discard accepted conns
	// RemoteConnMode overrides remoteEcho/remoteDownloadFeed per accept ("discard" | "feed").
	RemoteConnMode     func() string
	onRemoteAccept     func()
	WriteQueueMetrics  *fwd.WriteQueueMetrics
	IngressWakeFlushes *atomic.Int32
	OutboundWakeCalls  *atomic.Int32
	EgressWakeFlushes  *atomic.Int32
}

func startConnectIPUploadHarness(t *testing.T, link packetLink, opts ...connectIPUploadHarnessOpts) *connectIPUploadHarness {
	t.Helper()
	var o connectIPUploadHarnessOpts
	if len(opts) > 0 {
		o = opts[0]
	}
	clientSess, serverSess := link.endpoints()
	peer := netip.MustParsePrefix("198.18.0.2/32")

	clientNS, err := newConnectIPTCPNetstack(context.Background(), clientSess, connectIPHarnessNetstackOpts(o))
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
		fwdOpts := fwd.ConnectIPTCPForwarderOptions{AllowPrivateTargets: true}
		if o.WriteQueueMetrics != nil {
			fwdOpts.WriteQueueMetrics = o.WriteQueueMetrics
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

// TestWindowedPacketBridgeDownloadBand checks S2C window + client ACK credit in isolation.
func TestWindowedPacketBridgeDownloadBand(t *testing.T) {
	const duration = 400 * time.Millisecond
	client, server := newWindowedPacketPair(35*time.Millisecond, 64*1024)
	defer client.Close()
	defer server.Close()

	src := tcpip.AddrFrom4([4]byte{198, 18, 0, 1})
	dst := tcpip.AddrFrom4([4]byte{198, 18, 0, 2})
	payload := make([]byte, 1200)

	var total atomic.Int64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 2048)
		for {
			select {
			case <-stop:
				return
			default:
			}
			n, err := client.ReadPacket(buf)
			if err != nil {
				return
			}
			total.Add(int64(n))
			ackPkt := fwd.BuildIPv4TCPPacket(dst, src, 443, 40000, 1, 1, header.TCPFlagAck, 65535, nil, nil)
			if _, err := client.WritePacket(ackPkt); err != nil {
				return
			}
		}
	}()

	deadline := time.Now().Add(duration)
	var seq uint32 = 1
	go func() {
		for time.Now().Before(deadline) {
			dataPkt := fwd.BuildIPv4TCPPacket(src, dst, 40000, 443, seq, 1, header.TCPFlagPsh|header.TCPFlagAck, 65535, payload, nil)
			if _, err := server.WritePacket(dataPkt); err != nil {
				return
			}
			seq += uint32(len(payload))
		}
	}()
	time.Sleep(duration)
	close(stop)
	wg.Wait()

	n := total.Load()
	mbps := float64(n*8) / duration.Seconds() / 1e6
	t.Logf("windowed bridge download band: %.1f Mbit/s (%d bytes)", mbps, n)
	if mbps < connectIPLocalizeCeilingMin || mbps > connectIPLocalizeCeilingMax {
		t.Fatalf("bridge download %.1f Mbit/s want %.0f–%.0f", mbps, connectIPLocalizeCeilingMin, connectIPLocalizeCeilingMax)
	}
}

// TestMasqueConnectIPLocalizeBottleneck localizes connect-ip TUN upload (~15 Mbit/s field).
func TestMasqueConnectIPLocalizeBottleneck(t *testing.T) {
	const duration = 400 * time.Millisecond

	l0 := benchConnectIPUploadLayer(t, "L0", nil, duration)
	l1 := benchConnectIPUploadLayer(t, "L1", instantPacketLink{}, duration)
	l2 := benchConnectIPUploadLayer(t, "L2", windowedPacketLink{
		rtt:         localizeBenchRTT,
		windowBytes: 16 << 20,
	}, duration)
	l3 := benchConnectIPUploadLayer(t, "L3", benchWindowedPacketLink(), duration)
	l256 := benchConnectIPUploadLayer(t, "L256", windowedPacketLink{
		rtt:         localizeBenchRTT,
		windowBytes: 256 * 1024,
	}, duration)

	for _, r := range []connectIPUploadBenchResult{l0, l1, l2, l3, l256} {
		if r.err != nil {
			t.Fatalf("%s: %v", r.layer, r.err)
		}
		t.Logf("connect-ip localize %s: %.1f Mbit/s (%d bytes)", r.layer, r.mbps, r.bytes)
	}

	if l1.mbps < connectIPLocalizeFastMbps {
		t.Fatalf("upload L1 slow: %.1f Mbit/s (want >= %.0f)", l1.mbps, connectIPLocalizeFastMbps)
	}
	if l3.mbps < connectIPLocalizeCeilingMin || l3.mbps > connectIPLocalizeCeilingMax {
		t.Fatalf("upload L3 windowed: %.1f Mbit/s (want %.0f–%.0f)", l3.mbps, connectIPLocalizeCeilingMin, connectIPLocalizeCeilingMax)
	}

	v := verdictConnectIPUpload(l0, l1, l3)
	t.Logf("connect-ip localize verdict: %s", v)
}

// TestConnectIPLocalizeForwarderWakeAndWriteQueueMetrics ties client egress wake hooks and forwarder
// writeCh occupancy under bench-shaped windowed upload (~64 KiB / 35 ms RTT).
func TestConnectIPLocalizeForwarderWakeAndWriteQueueMetrics(t *testing.T) {
	inj := newLocalizeInjectors()
	h := startConnectIPUploadHarness(t, benchWindowedPacketLink(), inj.connectIPOpts())
	defer h.close()

	conn := h.dialRemote(t)
	defer conn.Close()

	n, mbps, err := measureTCPUploadMbps(conn, 400*time.Millisecond)
	if err != nil {
		t.Fatalf("windowed upload: %v", err)
	}
	if n < 32*1024 {
		t.Fatalf("windowed upload=%d bytes too small for wake+queue profiling", n)
	}

	depthHigh := inj.WriteQueueMetrics.DepthHigh.Load()
	calls := inj.OutboundWakeCalls.Load()
	flushes := inj.IngressWakeFlushes.Load()
	t.Logf("forwarder wake+queue: depthHigh=%d outboundWake=%d ingressFlush=%d upload=%.1f Mbit/s (%d bytes)",
		depthHigh, calls, flushes, mbps, n)

	if depthHigh == 0 {
		t.Fatal("expected writeCh occupancy under windowed link")
	}
	if depthHigh >= uint64(fwd.WriteQueueDepth) {
		t.Fatalf("writeCh depthHigh=%d must stay below capacity %d", depthHigh, fwd.WriteQueueDepth)
	}
	if calls == 0 {
		t.Fatal("expected client outbound wake hook during windowed upload")
	}
	if mbps < connectIPLocalizeCeilingMin || mbps > connectIPLocalizeCeilingMax {
		t.Fatalf("upload %.1f Mbit/s want %.0f–%.0f", mbps, connectIPLocalizeCeilingMin, connectIPLocalizeCeilingMax)
	}
}

// TestConnectIPLocalizeForwarderDownloadWindowedWriteTo (S66, S72): forwarder download under
// bench-shaped windowed packet link via WriteTo drain (prod route writer_to pattern).
func TestConnectIPLocalizeForwarderDownloadWindowedWriteTo(t *testing.T) {
	var metrics fwd.WriteQueueMetrics
	h := startConnectIPDownloadHarness(t, benchWindowedPacketLink(), connectIPUploadHarnessOpts{WriteQueueMetrics: &metrics})
	defer h.close()

	conn := h.dialRemote(t)
	defer conn.Close()

	n, mbps, err := measureTCPDownloadWriteToMbps(benchConnWriteTo{conn}, localizeBenchDuration)
	if err != nil {
		t.Fatalf("windowed WriteTo download: %v", err)
	}
	if n < localizeBenchMinBytes {
		t.Fatalf("bytes=%d want >= %d (forwarder download localize contract)", n, localizeBenchMinBytes)
	}
	// WriteTo forwarder path runs ~4–5 Mbit/s (Read-path L3 band: TestMasqueConnectIPLocalizeDownload).
	const forwarderWriteToMbpsFloor = 3.5
	if mbps < forwarderWriteToMbpsFloor || mbps > connectIPLocalizeCeilingMax {
		t.Fatalf("WriteTo download %.1f Mbit/s want %.1f–%.0f", mbps, forwarderWriteToMbpsFloor, connectIPLocalizeCeilingMax)
	}

	depthHigh := metrics.DepthHigh.Load()
	t.Logf("forwarder download windowed WriteTo: depthHigh=%d bytes=%d mbps=%.1f", depthHigh, n, mbps)
	if depthHigh > 1 {
		t.Fatalf("download DATA writeCh depthHigh=%d want <= 1 (ACK-only on queue)", depthHigh)
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

func outboundWakeHook(calls *atomic.Int32) func() {
	if calls == nil {
		return nil
	}
	return func() { calls.Add(1) }
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

func connectIPHarnessNetstackOpts(o connectIPUploadHarnessOpts) connectIPTCPNetstackOptions {
	return connectIPTCPNetstackOptions{
		LocalIPv4:             netip.MustParseAddr("198.18.0.2"),
		LocalIPv6:             netip.MustParseAddr("fd00::2"),
		MTU:                   1372,
		OnOutboundQueued:      outboundWakeHook(o.OutboundWakeCalls),
		OnEgressBatchComplete: egressBatchWakeHook(o.EgressWakeFlushes),
	}
}

func startConnectIPLocalizePipeHarness(t *testing.T, clientSess, serverSess IPPacketSession, opts ...connectIPUploadHarnessOpts) *connectIPUploadHarness {
	t.Helper()
	var o connectIPUploadHarnessOpts
	if len(opts) > 0 {
		o = opts[0]
	}
	peer := netip.MustParsePrefix("198.18.0.2/32")
	clientNS, err := newConnectIPTCPNetstack(context.Background(), clientSess, connectIPHarnessNetstackOpts(o))
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
		fwdOpts := fwd.ConnectIPTCPForwarderOptions{AllowPrivateTargets: true}
		if o.WriteQueueMetrics != nil {
			fwdOpts.WriteQueueMetrics = o.WriteQueueMetrics
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

// TestMasqueConnectIPLocalizeDownload checks instant L1 and windowed L3 download bands.
func TestMasqueConnectIPLocalizeDownload(t *testing.T) {
	const duration = 400 * time.Millisecond

	l0 := benchConnectIPDownloadLayer(t, "L0", nil, duration)
	l1 := benchConnectIPDownloadLayer(t, "L1", instantPacketLink{}, duration)
	l3 := benchConnectIPDownloadLayer(t, "L3", benchWindowedPacketLink(), duration)

	for _, r := range []connectIPUploadBenchResult{l0, l1, l3} {
		if r.err != nil {
			t.Fatalf("%s: %v", r.layer, r.err)
		}
		t.Logf("connect-ip localize download %s: %.1f Mbit/s (%d bytes)", r.layer, r.mbps, r.bytes)
	}

	if l1.mbps < connectIPLocalizeFastMbps {
		t.Fatalf("download L1 slow: %.1f Mbit/s (want >= %.0f)", l1.mbps, connectIPLocalizeFastMbps)
	}
	if l3.mbps < connectIPLocalizeCeilingMin || l3.mbps > connectIPLocalizeCeilingMax {
		t.Fatalf("download L3 windowed: %.1f Mbit/s (want %.0f–%.0f)", l3.mbps, connectIPLocalizeCeilingMin, connectIPLocalizeCeilingMax)
	}

	v := verdictConnectIPDownload(l0, l1, l3)
	t.Logf("connect-ip localize download verdict: %s", v)
}

// TestLocalizeConnectIPNativeH3PipeL1Reference logs in-proc pipe L1 ceiling (no QUIC) for the
// same KPI class as native H3 GATE. A large pipe-vs-H3 gap localizes the QUIC dataplane.
func TestLocalizeConnectIPNativeH3PipeL1Reference(t *testing.T) {
	const benchDur = 2 * time.Second
	r := benchConnectIPDownloadLayer(t, "L1", instantPacketLink{}, benchDur)
	if r.err != nil {
		t.Fatalf("pipe L1 download: %v", r.err)
	}
	t.Logf("connect-ip pipe L1 reference download: %.1f Mbit/s (native H3 GATE target %.0f)", r.mbps, connectIPLocalizeFastMbps)
	if r.mbps < connectIPLocalizeFastMbps {
		t.Fatalf("pipe L1 reference below in-proc floor: %.1f < %.0f", r.mbps, connectIPLocalizeFastMbps)
	}
}

// (upload/download ≥80 Mbit/s in-proc). Docker tcp_down≥350 @ netem: TestMasqueDockerBenchConnectIPH3TunKPIContract + bench-history.
func TestConnectIPDockerTUNKPIInProcGuard(t *testing.T) {
	t.Run("upload", func(t *testing.T) {
		h := startConnectIPUploadHarness(t, instantPacketLink{})
		defer h.close()
		conn := h.dialRemote(t)
		defer conn.Close()
		bytes, mbps, err := measureTCPUploadMbps(conn, localizeBenchDuration)
		if err != nil {
			t.Fatalf("upload: %v", err)
		}
		t.Logf("connect-ip docker upload KPI proxy: %.1f Mbit/s (%d B)", mbps, bytes)
		if mbps < connectIPLocalizeFastMbps {
			t.Fatalf("upload %.1f Mbit/s want >= %.0f (docker tcp_up KPI)", mbps, connectIPLocalizeFastMbps)
		}
	})

	t.Run("download", func(t *testing.T) {
		h := startConnectIPDownloadHarness(t, instantPacketLink{})
		defer h.close()
		conn := h.dialRemote(t)
		defer conn.Close()
		bytes, mbps, err := measureTCPDownloadMbps(conn, localizeBenchDuration)
		if err != nil {
			t.Fatalf("download: %v", err)
		}
		t.Logf("connect-ip docker download KPI proxy: %.1f Mbit/s (%d B)", mbps, bytes)
		if mbps < connectIPLocalizeFastMbps {
			t.Fatalf("download %.1f Mbit/s want >= %.0f (docker in-proc L1 floor)", mbps, connectIPLocalizeFastMbps)
		}
	})
}

// TestConnectIPForwarderDownloadWindowedBand (S72): L3 forwarder download stays in windowed ceiling band (Read path).
func TestConnectIPForwarderDownloadWindowedBand(t *testing.T) {
	r := benchConnectIPDownloadLayer(t, "L3", benchWindowedPacketLink(), localizeBenchDuration)
	if r.err != nil {
		t.Fatalf("L3 download: %v", r.err)
	}
	t.Logf("forwarder download windowed band: %.1f Mbit/s (%d bytes)", r.mbps, r.bytes)
	if r.mbps < connectIPLocalizeCeilingMin || r.mbps > connectIPLocalizeCeilingMax {
		t.Fatalf("L3 download %.1f Mbit/s want %.0f–%.0f", r.mbps, connectIPLocalizeCeilingMin, connectIPLocalizeCeilingMax)
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

// serialWriteShim models TUN-style single-threaded WritePacket (mutex + extra copy per datagram).
type serialWriteShim struct {
	inner IPPacketSession
	mu    sync.Mutex
}

func (s *serialWriteShim) ReadPacket(buffer []byte) (int, error) {
	return s.inner.ReadPacket(buffer)
}

func (s *serialWriteShim) WritePacket(buffer []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	dup := make([]byte, len(buffer))
	copy(dup, buffer)
	return s.inner.WritePacket(dup)
}

func (s *serialWriteShim) Close() error {
	return s.inner.Close()
}

// asyncWriteShim mirrors ClientPacketSession batched egress for in-proc TUN proxy tests.
type asyncWriteShim struct {
	inner      IPPacketSession
	once       sync.Once
	closeOnce  sync.Once
	ch         chan []byte
	stop       chan struct{}
	wg         sync.WaitGroup
	closed     atomic.Bool
}

func newAsyncWriteShim(inner IPPacketSession) *asyncWriteShim {
	return &asyncWriteShim{inner: inner}
}

func (s *asyncWriteShim) ensureWriter() {
	s.once.Do(func() {
		s.ch = make(chan []byte, 8192)
		s.stop = make(chan struct{})
		s.wg.Add(1)
		go s.runWriter()
	})
}

func (s *asyncWriteShim) runWriter() {
	defer s.wg.Done()
	for {
		select {
		case <-s.stop:
			return
		case pkt := <-s.ch:
			batch := [][]byte{pkt}
			for len(batch) < 64 {
				select {
				case p := <-s.ch:
					batch = append(batch, p)
				default:
					goto send
				}
			}
		send:
			for _, p := range batch {
				_, _ = s.inner.WritePacket(p)
			}
		}
	}
}

func (s *asyncWriteShim) ReadPacket(buffer []byte) (int, error) {
	return s.inner.ReadPacket(buffer)
}

func (s *asyncWriteShim) WritePacket(buffer []byte) ([]byte, error) {
	s.ensureWriter()
	if s.closed.Load() {
		return s.inner.WritePacket(buffer)
	}
	dup := make([]byte, len(buffer))
	copy(dup, buffer)
	select {
	case <-s.stop:
		return s.inner.WritePacket(buffer)
	case s.ch <- dup:
		return nil, nil
	default:
		return s.inner.WritePacket(buffer)
	}
}

func (s *asyncWriteShim) Close() error {
	s.closeOnce.Do(func() {
		if s.ch != nil {
			s.closed.Store(true)
			close(s.stop)
			s.wg.Wait()
		}
	})
	return s.inner.Close()
}

type serialWriteLink struct {
	inner packetLink
}

type tunSerialAsyncLink struct {
	inner packetLink
}

func (l tunSerialAsyncLink) endpoints() (IPPacketSession, IPPacketSession) {
	client, server := l.inner.endpoints()
	client = &serialWriteShim{inner: newAsyncWriteShim(client)}
	return client, server
}

func (l serialWriteLink) endpoints() (IPPacketSession, IPPacketSession) {
	client, server := l.inner.endpoints()
	return &serialWriteShim{inner: client}, server
}

// TestLocalizeConnectIPUploadTUNEgressSerialWrite localizes Docker TUN upload gap: serialized
// WritePacket + copy per datagram. asyncWriteShim (prod ClientPacketSession path) should recover most of the gap.
func TestLocalizeConnectIPUploadTUNEgressSerialWrite(t *testing.T) {
	const duration = localizeBenchDuration
	baseline := benchConnectIPUploadLayer(t, "L1-instant", instantPacketLink{}, duration)
	serial := benchConnectIPUploadLayer(t, "L1-serial", serialWriteLink{inner: instantPacketLink{}}, duration)
	recovered := benchConnectIPUploadLayer(t, "L1-serial+async", tunSerialAsyncLink{inner: instantPacketLink{}}, duration)
	if baseline.err != nil || serial.err != nil || recovered.err != nil {
		t.Fatalf("bench error baseline=%v serial=%v recovered=%v", baseline.err, serial.err, recovered.err)
	}
	serialRatio := serial.mbps / baseline.mbps
	recoveredRatio := recovered.mbps / baseline.mbps
	recoverVsSerial := recovered.mbps / serial.mbps
	t.Logf("TUN egress proxy: baseline=%.1f serial=%.1f (ratio=%.2f) serial+async=%.1f (ratio=%.2f recover/serial=%.2f)",
		baseline.mbps, serial.mbps, serialRatio, recovered.mbps, recoveredRatio, recoverVsSerial)
	const tunAsyncRecoveryVsSerial = 0.85
	if recoverVsSerial < tunAsyncRecoveryVsSerial {
		t.Fatalf("serial+async %.1f did not recover serial %.1f (need >= %.0f%%)",
			recovered.mbps, serial.mbps, tunAsyncRecoveryVsSerial*100)
	}
	if recovered.mbps < connectIPSynthRegressionFloorUpMbps {
		t.Fatalf("serial+async %.1f < regression floor %.1f", recovered.mbps, connectIPSynthRegressionFloorUpMbps)
	}
	const tunProxyCollapseRatio = 0.55
	if serialRatio < tunProxyCollapseRatio && baseline.mbps >= connectIPSynthRegressionFloorUpMbps {
		t.Logf("OPEN: serial/tun proxy ratio %.2f — Docker upload gap likely TUN WritePacket path", serialRatio)
	}
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

// TestMasqueConnectIPLocalizeRecycle verifies bulk upload teardown (incl. benign 0x100)
// does not poison the packet plane before a fresh download flow.
func TestMasqueConnectIPLocalizeRecycle(t *testing.T) {
	const uploadDur = 300 * time.Millisecond
	const downloadDur = 400 * time.Millisecond

	rawClient, serverSess := instantPacketLink{}.endpoints()
	clientSess := &benignOnceWriteSession{inner: rawClient}
	var recyclePhase atomic.Int32
	h := startConnectIPLocalizePipeHarness(t, clientSess, serverSess, connectIPUploadHarnessOpts{
		RemoteConnMode: func() string {
			if recyclePhase.Load() == 0 {
				return "discard"
			}
			return "feed"
		},
	})
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

	recyclePhase.Store(1)
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
		windowBytes = localizeBenchWindowBytes
	}
	if rtt <= 0 {
		rtt = localizeBenchRTT
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
	mu               sync.Mutex
	cond             *sync.Cond
	rtt              time.Duration
	windowBytes      int
	inflightC2S      int
	inflightS2C      int
	pendingRelease   int
	pendingReleaseS2C int
	releaseTimer     *time.Timer
	clientRx         chan []byte
	serverRx         chan []byte
	closed           bool
}

func (b *windowedPacketBridge) write(role bridgeRole, pkt []byte) error {
	tcpPayload := -1
	tcpAckOnly := false
	tcpOK := false
	if payloadLen, ackOnly, ok := connectIPLocalizeTCPMeta(pkt); ok {
		tcpPayload = payloadLen
		tcpAckOnly = ackOnly
		tcpOK = true
	}
	isC2SData := role == bridgeRoleClient && tcpOK && tcpPayload > 0
	isS2CData := role == bridgeRoleServer && tcpOK && tcpPayload > 0
	isAck := tcpOK && tcpAckOnly

	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return net.ErrClosed
	}
	if isC2SData {
		charge := tcpPayload
		for b.inflightC2S+charge > b.windowBytes && !b.closed {
			b.cond.Wait()
		}
		if b.closed {
			b.mu.Unlock()
			return net.ErrClosed
		}
		b.inflightC2S += charge
	}
	if isS2CData {
		charge := tcpPayload
		for b.inflightS2C+charge > b.windowBytes && !b.closed {
			b.cond.Wait()
		}
		if b.closed {
			b.mu.Unlock()
			return net.ErrClosed
		}
		b.inflightS2C += charge
	}
	b.mu.Unlock()

	dst := b.serverRx
	if role == bridgeRoleServer {
		dst = b.clientRx
	}
	p := append([]byte(nil), pkt...)
	if isAck && role == bridgeRoleServer && b.rtt > 0 {
		// Upload ACK clock: server→client ACK delivery is RTT-delayed.
		time.Sleep(b.rtt)
	}

	deliver := func() error {
		select {
		case dst <- p:
			if isAck {
				credit := connectIPLocalizeAckCredit(pkt)
				if role == bridgeRoleServer {
					b.releaseC2S(credit)
				} else {
					b.scheduleReleaseS2C(credit)
				}
			}
			return nil
		default:
			if isAck {
				credit := connectIPLocalizeAckCredit(pkt)
				if role == bridgeRoleServer {
					b.releaseC2S(credit)
				} else {
					b.scheduleReleaseS2C(credit)
				}
			}
			return io.ErrShortBuffer
		}
	}
	return deliver()
}

func connectIPLocalizeIsIPv4TCP(pkt []byte) bool {
	return len(pkt) >= 20 && pkt[0]>>4 == 4 && pkt[9] == 6
}

func connectIPLocalizeTCPMeta(pkt []byte) (payloadLen int, ackOnly bool, ok bool) {
	if !connectIPLocalizeIsIPv4TCP(pkt) {
		return -1, false, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl+14 > len(pkt) {
		return -1, false, false
	}
	doff := int(pkt[ihl+12]>>4) * 4
	if doff < 20 || ihl+doff > len(pkt) {
		return -1, false, false
	}
	payloadLen = len(pkt) - ihl - doff
	ackOnly = payloadLen == 0 && pkt[ihl+13]&0x10 != 0
	return payloadLen, ackOnly, true
}

func connectIPLocalizeTCPPayloadLen(pkt []byte) int {
	payloadLen, _, ok := connectIPLocalizeTCPMeta(pkt)
	if !ok {
		return -1
	}
	return payloadLen
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

func (b *windowedPacketBridge) scheduleReleaseS2C(credit int) {
	if credit <= 0 {
		return
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.pendingReleaseS2C += credit
	if b.releaseTimer == nil && b.rtt > 0 {
		b.releaseTimer = time.AfterFunc(b.rtt, b.flushRelease)
	} else if b.releaseTimer == nil {
		b.flushReleaseS2CLocked()
	}
	b.mu.Unlock()
}

func (b *windowedPacketBridge) flushReleaseS2CLocked() {
	credit := b.pendingReleaseS2C
	b.pendingReleaseS2C = 0
	if credit > 0 {
		b.inflightS2C -= credit
		if b.inflightS2C < 0 {
			b.inflightS2C = 0
		}
		b.cond.Broadcast()
	}
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
	b.flushReleaseS2CLocked()
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
