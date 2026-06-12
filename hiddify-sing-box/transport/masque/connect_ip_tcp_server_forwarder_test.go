package masque

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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
	h := startConnectIPUploadHarness(t, windowedPacketLink{
		rtt:         35 * time.Millisecond,
		windowBytes: 64 * 1024,
	}, connectIPUploadHarnessOpts{WriteQueueMetrics: &metrics})
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
	const windowSegments = 64 * 1024 / 1300
	if depthHigh > windowSegments+32 {
		t.Fatalf("writeCh depthHigh=%d exceeds windowed link budget (~%d segments)", depthHigh, windowSegments)
	}
}

