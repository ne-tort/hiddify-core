package masque

// Forwarder unit gate implementations (W-IP-10 IP-10-PR0). Harness: connectip_forwarder_harness.go.

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
	cip "github.com/sagernet/sing-box/transport/masque/connectip"
	fwd "github.com/sagernet/sing-box/transport/masque/forwarder"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	M "github.com/sagernet/sing/common/metadata"
)

type forwarderSynAckSession struct {
	ns *cip.Netstack
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
	opts := fwd.BuildSynAckTCPOptions(synOpts, 0)
	synAck := fwd.BuildIPv4TCPPacket(
		header.IPv4(pkt).DestinationAddress(), header.IPv4(pkt).SourceAddress(),
		tc.DestinationPort(), tc.SourcePort(),
		0x9e3779b9, irs+1,
		header.TCPFlagSyn|header.TCPFlagAck,
		65535, nil, opts,
	)
	s.ns.InjectInboundClone(synAck)
	return nil, nil
}

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

type retryableWritePipeLink struct {
	failCount int32
}

func (l retryableWritePipeLink) endpoints() (IPPacketSession, IPPacketSession) {
	c, s := instantPacketLink{}.endpoints()
	wrap := &retryableThenOKServerSession{inner: s}
	wrap.failRemaining.Store(l.failCount)
	return c, wrap
}

const forwarderSynReadyAfterUploadMax = 750 * time.Millisecond

func gateConnectIPTCPNetstackHandshakeWithForwarderSynAck(t *testing.T) {
	t.Helper()
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
	ns, err := cip.NewNetstackForSession(context.Background(), sess, cip.NetstackOptions{
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

func gateConnectIPTCPForwarderSYNRetransmitSingleDial(t *testing.T) {
	t.Helper()
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

func gateConnectIPTCPForwarderPipeBulk(t *testing.T) {
	t.Helper()
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

func gateConnectIPTCPForwarderWriteQueueDepthWindowedLink(t *testing.T) {
	t.Helper()
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
	const windowSegments = localizeBenchWindowBytes / 1300
	if depthHigh > windowSegments+32 {
		t.Fatalf("writeCh depthHigh=%d exceeds windowed link budget (~%d segments)", depthHigh, windowSegments)
	}
}

func gateForwarderRestartReadinessSynDialAfterUpload(t *testing.T) {
	t.Helper()
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

func gateConnectIPTCPForwarderServerReadBenign0x100NotFatal(t *testing.T) {
	t.Helper()
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

func gateConnectIPTCPForwarderWritePacketFailThenOKNoSilentDrop(t *testing.T) {
	t.Helper()
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
