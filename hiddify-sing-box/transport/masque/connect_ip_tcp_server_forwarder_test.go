package masque

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	fwd "github.com/sagernet/sing-box/transport/masque/forwarder"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	M "github.com/sagernet/sing/common/metadata"
)

// forwarderSynAckSession replies to outbound SYNs with a SYN-ACK built by the CONNECT-IP forwarder.
type forwarderSynAckSession struct {
	ns *connectIPTCPNetstack
}

func (s *forwarderSynAckSession) ReadPacket([]byte) (int, error) {
	return 0, io.EOF
}

func (s *forwarderSynAckSession) Close() error { return nil }

func (s *forwarderSynAckSession) WritePacket(pkt []byte) ([]byte, error) {
	if len(pkt) < header.IPv4MinimumSize || pkt[0]>>4 != 4 || pkt[9] != uint8(header.TCPProtocolNumber) {
		return nil, nil
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl+header.TCPMinimumSize > len(pkt) {
		return nil, nil
	}
	tc := header.TCP(pkt[ihl:])
	if tc.Flags()&(header.TCPFlagSyn|header.TCPFlagAck) != header.TCPFlagSyn {
		return nil, nil
	}
	irs := tc.SequenceNumber()
	synOpts := header.ParseSynOptions(tc.Options(), false)
	opts := fwd.BuildSynAckTCPOptions(synOpts)
	synAck := fwd.BuildIPv4TCPPacket(
		iphFrom(pkt).DestinationAddress(), iphFrom(pkt).SourceAddress(),
		tc.DestinationPort(), tc.SourcePort(),
		0x9e3779b9, irs+1,
		header.TCPFlagSyn|header.TCPFlagAck,
		65535, nil, opts,
	)
	s.ns.InjectInboundClone(synAck)
	return nil, nil
}

func iphFrom(pkt []byte) header.IPv4 { return header.IPv4(pkt) }

func TestConnectIPTCPNetstackHandshakeWithForwarderSynAck(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_ = c.Close()
	}()

	sess := &forwarderSynAckSession{}
	ns, err := newConnectIPTCPNetstack(context.Background(), sess, connectIPTCPNetstackOptions{
		LocalIPv4: netip.MustParseAddr("198.18.0.1"),
		MTU:       1500,
	})
	if err != nil {
		t.Fatalf("new netstack: %v", err)
	}
	sess.ns = ns
	t.Cleanup(func() { _ = ns.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(1)
	var dialErr error
	go func() {
		defer wg.Done()
		_, dialErr = ns.DialContext(ctx, M.ParseSocksaddrHostPort("127.0.0.1", port))
	}()
	wg.Wait()
	if dialErr != nil {
		t.Fatalf("dial: %v", dialErr)
	}
}

// --- pipe harness (RunConnectIPTCPPacketPlaneForwarder + packet pipe) ---

type synDupeClientSession struct {
	IPPacketSession
	once sync.Once
}

func (s *synDupeClientSession) WritePacket(pkt []byte) ([]byte, error) {
	icmp, err := s.IPPacketSession.WritePacket(pkt)
	if err != nil {
		return icmp, err
	}
	if isTCPPacketSynOnly(pkt) {
		s.once.Do(func() {
			dup := append([]byte(nil), pkt...)
			time.Sleep(30 * time.Millisecond)
			_, _ = s.IPPacketSession.WritePacket(dup)
		})
	}
	return icmp, nil
}

func isTCPPacketSynOnly(pkt []byte) bool {
	if len(pkt) < header.IPv4MinimumSize || pkt[0]>>4 != 4 || pkt[9] != uint8(header.TCPProtocolNumber) {
		return false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl+header.TCPMinimumSize > len(pkt) {
		return false
	}
	tc := header.TCP(pkt[ihl:])
	return tc.Flags()&(header.TCPFlagSyn|header.TCPFlagAck) == header.TCPFlagSyn
}

type forwarderPipeLink struct {
	dupeSyn bool
}

func (l forwarderPipeLink) endpoints() (IPPacketSession, IPPacketSession) {
	c, s := newPacketPipePair()
	if l.dupeSyn {
		return &synDupeClientSession{IPPacketSession: c}, s
	}
	return c, s
}

type forwarderPipeHarness struct {
	*connectIPUploadHarness
	acceptCount atomic.Int32
}

func startForwarderPipeHarness(t *testing.T, link packetLink, echo bool) *forwarderPipeHarness {
	t.Helper()
	fh := &forwarderPipeHarness{}
	opts := connectIPUploadHarnessOpts{remoteEcho: echo}
	if echo {
		opts.onRemoteAccept = func() { fh.acceptCount.Add(1) }
	}
	fh.connectIPUploadHarness = startConnectIPUploadHarness(t, link, opts)
	return fh
}

func TestConnectIPTCPForwarderPipeSYNHandshake(t *testing.T) {
	t.Parallel()
	h := startForwarderPipeHarness(t, forwarderPipeLink{}, true)
	defer h.close()

	conn := h.dialRemote(t)
	defer conn.Close()

	msg := []byte("connect-ip-forwarder-syn")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(buf, msg) {
		t.Fatalf("echo mismatch: got %q want %q", buf, msg)
	}
}

func TestConnectIPTCPForwarderSYNRetransmitSingleDial(t *testing.T) {
	t.Parallel()
	h := startForwarderPipeHarness(t, forwarderPipeLink{dupeSyn: true}, true)
	defer h.close()

	conn := h.dialRemote(t)
	defer conn.Close()

	deadline := time.Now().Add(2 * time.Second)
	for h.acceptCount.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if n := h.acceptCount.Load(); n != 1 {
		t.Fatalf("remote accept count=%d want 1 (retransmitted SYN must not re-dial)", n)
	}

	msg := []byte("after-retransmit")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(buf, msg) {
		t.Fatalf("echo mismatch after retransmit")
	}
}

func TestConnectIPTCPForwarderPipeBulk(t *testing.T) {
	t.Parallel()
	h := startForwarderPipeHarness(t, forwarderPipeLink{}, false)
	defer h.close()

	conn := h.dialRemote(t)
	defer conn.Close()

	const wantMin = 256 * 1024
	n, _, err := measureTCPUploadMbps(conn, 400*time.Millisecond)
	if err != nil {
		t.Fatalf("bulk upload: %v", err)
	}
	if n < wantMin {
		t.Fatalf("bulk upload=%d bytes want >= %d", n, wantMin)
	}
}

// TestConnectIPTCPForwarderWriteQueueDepthWindowedLink profiles forwarder writeCh under
// bench-shaped windowed backpressure (~64 KiB / 35 ms RTT).
func TestConnectIPTCPForwarderWriteQueueDepthWindowedLink(t *testing.T) {
	t.Parallel()
	var metrics fwd.WriteQueueMetrics
	h := startConnectIPUploadHarness(t, benchWindowedPacketLink(), connectIPUploadHarnessOpts{WriteQueueMetrics: &metrics})
	defer h.close()

	conn := h.dialRemote(t)
	defer conn.Close()

	n, mbps, err := measureTCPUploadMbps(conn, 400*time.Millisecond)
	if err != nil {
		t.Fatalf("windowed upload: %v", err)
	}
	if n < 32*1024 {
		t.Fatalf("windowed upload=%d bytes too small for queue profiling", n)
	}

	depthHigh := metrics.DepthHigh.Load()
	depth := metrics.Depth.Load()
	t.Logf("forwarder writeCh: depth=%d depthHigh=%d upload=%.1f Mbit/s (%d bytes)",
		depth, depthHigh, mbps, n)

	if depthHigh == 0 {
		t.Fatal("expected writeCh occupancy under windowed link")
	}
	if depthHigh >= uint64(fwd.WriteQueueDepth) {
		t.Fatalf("writeCh depthHigh=%d must stay below capacity %d", depthHigh, fwd.WriteQueueDepth)
	}
	// Windowed link caps ~64 KiB in flight; queue should reflect backpressure, not stay empty.
	const windowSegments = localizeBenchWindowBytes / 1300
	if depthHigh > windowSegments+32 {
		t.Fatalf("writeCh depthHigh=%d exceeds windowed link budget (~%d segments)", depthHigh, windowSegments)
	}
}

// TestConnectIPTCPForwarderDownloadWindowedLinkThroughput checks download DATA bypasses writeCh
// and sustains goodput under bench-shaped windowed backpressure (~64 KiB / 35 ms RTT).
func TestConnectIPTCPForwarderDownloadWindowedLinkThroughput(t *testing.T) {
	t.Parallel()
	var metrics fwd.WriteQueueMetrics
	h := startConnectIPDownloadHarness(t, benchWindowedPacketLink(), connectIPUploadHarnessOpts{WriteQueueMetrics: &metrics})
	defer h.close()

	conn := h.dialRemote(t)
	defer conn.Close()

	n, mbps, err := measureTCPDownloadMbps(conn, 800*time.Millisecond)
	if err != nil {
		t.Fatalf("windowed download: %v", err)
	}
	if n < 8*1024 {
		t.Fatalf("windowed download=%d bytes too small", n)
	}
	depthHigh := metrics.DepthHigh.Load()
	t.Logf("forwarder download windowed: %.1f Mbit/s (%d bytes) writeCh depthHigh=%d",
		mbps, n, depthHigh)
	// Handshake ACK/FIN may use writeCh; bulk DATA must not deepen the queue.
	if depthHigh > 1 {
		t.Fatalf("download DATA writeCh depthHigh=%d want <= 1 (ACK-only on queue)", depthHigh)
	}
	const windowedDownloadMbpsFloor = 0.2 // bridge models RTT per server→client segment
	if mbps < windowedDownloadMbpsFloor {
		t.Fatalf("windowed download %.1f Mbit/s want >= %.1f", mbps, windowedDownloadMbpsFloor)
	}
}

// TestConnectIPTCPForwarderPipeUploadThenDownload verifies one forwarder instance serves
// bulk upload teardown and a fresh download without server restart.
func TestConnectIPTCPForwarderPipeUploadThenDownload(t *testing.T) {
	t.Parallel()
	h := startConnectIPDownloadHarness(t, instantPacketLink{})
	defer h.close()

	upConn := h.dialRemote(t)
	upBytes, upMbps, err := measureTCPUploadMbps(upConn, 300*time.Millisecond)
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	if err := upConn.Close(); err != nil {
		t.Fatalf("close upload conn: %v", err)
	}
	flushConnectIPEgressAfterClose(h)

	downConn := h.dialRemote(t)
	defer downConn.Close()
	downBytes, downMbps, err := measureTCPDownloadMbps(downConn, 400*time.Millisecond)
	if err != nil {
		t.Fatalf("download after upload: %v", err)
	}
	t.Logf("forwarder pipe upload: %.1f Mbit/s (%d bytes)", upMbps, upBytes)
	t.Logf("forwarder pipe download: %.1f Mbit/s (%d bytes)", downMbps, downBytes)
	if downBytes < 32*1024 {
		t.Fatalf("download after upload=%d bytes want >= 32KiB without server restart", downBytes)
	}
}

// forwarderSynReadyAfterUploadMax is the in-proc SYN dial budget after upload teardown.
// Docker/run_local.py recycle workaround is seconds-scale; this guard catches forwarder stalls only.
const forwarderSynReadyAfterUploadMax = 750 * time.Millisecond

// TestForwarderRestartReadinessSynDialAfterUpload verifies a fresh TCP dial (SYN) completes
// quickly after upload teardown on the same forwarder — parity with run_local.py TCP probe.
// Not parallel: latency guard is CPU-sensitive under full L3 gate load.
func TestForwarderRestartReadinessSynDialAfterUpload(t *testing.T) {
	h := startConnectIPDownloadHarness(t, instantPacketLink{})
	defer h.close()

	upConn := h.dialRemote(t)
	if _, err := upConn.Write([]byte("warmup")); err != nil {
		t.Fatalf("upload warmup: %v", err)
	}
	if err := upConn.Close(); err != nil {
		t.Fatalf("close upload: %v", err)
	}
	waitConnectIPEgressDrained(t, h)

	start := time.Now()
	downConn := h.dialRemote(t)
	latency := time.Since(start)
	if err := downConn.Close(); err != nil {
		t.Fatalf("close recycle dial: %v", err)
	}
	t.Logf("forwarder SYN-ready after upload recycle: %v", latency)
	if latency > forwarderSynReadyAfterUploadMax {
		t.Fatalf("SYN dial after upload recycle took %v want < %v", latency, forwarderSynReadyAfterUploadMax)
	}
}

// benignOnceReadServerSession injects one remote QUIC NO_ERROR (0x100) on the next server ReadPacket.
type benignOnceReadServerSession struct {
	inner IPPacketSession
	armed atomic.Bool
	fired atomic.Bool
}

func (s *benignOnceReadServerSession) ArmRead0x100() {
	s.armed.Store(true)
}

func (s *benignOnceReadServerSession) ReadPacket(buf []byte) (int, error) {
	if s.armed.Load() && !s.fired.Swap(true) {
		return 0, &quic.ApplicationError{ErrorCode: 0x100, Remote: true}
	}
	return s.inner.ReadPacket(buf)
}

func (s *benignOnceReadServerSession) WritePacket(pkt []byte) ([]byte, error) {
	return s.inner.WritePacket(pkt)
}

func (s *benignOnceReadServerSession) Close() error {
	return s.inner.Close()
}

// retryableThenOKServerSession fails WritePacket with a transient error N times, then delegates.
type retryableThenOKServerSession struct {
	inner         IPPacketSession
	failRemaining atomic.Int32
}

func (s *retryableThenOKServerSession) ReadPacket(buf []byte) (int, error) {
	return s.inner.ReadPacket(buf)
}

func (s *retryableThenOKServerSession) WritePacket(pkt []byte) ([]byte, error) {
	if s.failRemaining.Add(-1) >= 0 {
		return nil, &net.OpError{Op: "write", Err: errors.New("i/o timeout")}
	}
	return s.inner.WritePacket(pkt)
}

func (s *retryableThenOKServerSession) Close() error {
	return s.inner.Close()
}

// TestConnectIPTCPForwarderServerReadBenign0x100NotFatal verifies server read-path 0x100 is benign.
func TestConnectIPTCPForwarderServerReadBenign0x100NotFatal(t *testing.T) {
	t.Parallel()
	rawClient, rawServer := instantPacketLink{}.endpoints()
	serverSess := &benignOnceReadServerSession{inner: rawServer}
	t.Cleanup(func() {
		_ = rawClient.Close()
		_ = serverSess.Close()
	})

	serverConn := &forwarderPipeConn{
		IPPacketSession: serverSess,
		peerPrefixes:    []netip.Prefix{netip.MustParsePrefix("198.18.0.2/32")},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- fwd.RunConnectIPTCPPacketPlaneForwarder(ctx, serverConn, fwd.ConnectIPTCPForwarderOptions{
			AllowPrivateTargets: true,
		})
	}()

	serverSess.ArmRead0x100()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("forwarder exit: %v want nil on benign server read 0x100", err)
		}
	case <-ctx.Done():
		t.Fatal("timeout waiting for forwarder exit on benign server read 0x100")
	}
}

// retryableWritePipeLink wraps the server pipe endpoint with transient WritePacket failures.
type retryableWritePipeLink struct {
	failCount int32
}

func (l retryableWritePipeLink) endpoints() (IPPacketSession, IPPacketSession) {
	c, s := instantPacketLink{}.endpoints()
	wrap := &retryableThenOKServerSession{inner: s}
	wrap.failRemaining.Store(l.failCount)
	return c, wrap
}

// TestConnectIPTCPForwarderWritePacketFailThenOKNoSilentDrop verifies runWriteLoop retries transient
// WritePacket failures and still delivers ACK/data to the client.
func TestConnectIPTCPForwarderWritePacketFailThenOKNoSilentDrop(t *testing.T) {
	t.Parallel()
	h := startConnectIPUploadHarness(t, retryableWritePipeLink{failCount: 2}, connectIPUploadHarnessOpts{remoteEcho: true})
	defer h.close()

	conn := h.dialRemote(t)
	defer conn.Close()

	msg := []byte("forwarder-write-retry-no-drop")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo after transient WritePacket failures: %v", err)
	}
	if !bytes.Equal(buf, msg) {
		t.Fatalf("echo mismatch after WritePacket retry: got %q want %q", buf, msg)
	}

	n, _, err := measureTCPUploadMbps(conn, 200*time.Millisecond)
	if err != nil {
		t.Fatalf("bulk upload after WritePacket retry: %v", err)
	}
	if n < 32*1024 {
		t.Fatalf("bulk upload=%d bytes want >= 32KiB (silent drop would stall)", n)
	}
}

