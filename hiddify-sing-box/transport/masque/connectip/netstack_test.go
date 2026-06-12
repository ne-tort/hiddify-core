package connectip

import (
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
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv6"
	M "github.com/sagernet/sing/common/metadata"
)

type packetPipeSession struct {
	recvCh  chan []byte
	sendCh  chan []byte
	closeCh chan struct{}
	once    sync.Once
}

type failingReadSession struct {
	readCount atomic.Int32
}

func (s *failingReadSession) ReadPacket(_ []byte) (int, error) {
	if s.readCount.Add(1) == 1 {
		return 0, errors.New("packet plane closed")
	}
	return 0, net.ErrClosed
}

func (s *failingReadSession) WritePacket(buffer []byte) ([]byte, error) {
	return nil, nil
}

func (s *failingReadSession) Close() error { return nil }

type fatalWriteSession struct {
	closeCh chan struct{}
	once    sync.Once
}

func (s *fatalWriteSession) ReadPacket(_ []byte) (int, error) {
	<-s.closeCh
	return 0, net.ErrClosed
}

func (s *fatalWriteSession) WritePacket(_ []byte) ([]byte, error) {
	return nil, errors.New("fatal simulated write plane error")
}

func (s *fatalWriteSession) Close() error {
	s.once.Do(func() { close(s.closeCh) })
	return nil
}

type benignOnceWriteSession struct {
	inner PacketSession
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

type retryableThenOKWriteSession struct {
	failRemaining atomic.Int32
	written       atomic.Int32
}

func (s *retryableThenOKWriteSession) ReadPacket(_ []byte) (int, error) {
	return 0, net.ErrClosed
}

func (s *retryableThenOKWriteSession) WritePacket(_ []byte) ([]byte, error) {
	if s.failRemaining.Add(-1) >= 0 {
		return nil, context.DeadlineExceeded
	}
	s.written.Add(1)
	return nil, nil
}

func (s *retryableThenOKWriteSession) Close() error { return nil }

func TestIsBenignConnectIPEgressTeardownError(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"closed", net.ErrClosed, true},
		{"eof", io.EOF, true},
		{"closed_pipe", io.ErrClosedPipe, true},
		{"h3_no_error", &quic.ApplicationError{ErrorCode: 0x100, Remote: true}, true},
		{"other_app", &quic.ApplicationError{ErrorCode: 0x101, Remote: true}, false},
		{"timeout", context.DeadlineExceeded, false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := IsBenignEgressTeardownError(tc.err); got != tc.want {
				t.Fatalf("IsBenignEgressTeardownError(%v)=%v want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestConnectIPTCPNetstackFailWithErrorDoesNotClosePacketSession(t *testing.T) {
	sess := &packetPipeSession{recvCh: make(chan []byte, 8), sendCh: make(chan []byte, 8), closeCh: make(chan struct{})}
	stack, err := NewNetstack(context.Background(), sess, NetstackOptions{
		LocalIPv4: netip.MustParseAddr("198.18.0.2"),
		LocalIPv6: netip.MustParseAddr("fd00::2"),
	})
	if err != nil {
		t.Fatalf("create stack: %v", err)
	}
	defer stack.Close()
	stack.FailWithError(&quic.ApplicationError{ErrorCode: 0x100, Remote: true})
	select {
	case <-sess.closeCh:
		t.Fatal("packet session must not close on benign teardown error")
	default:
	}
}

type benignThenBlockWriteSession struct {
	writes atomic.Int32
	block  chan struct{}
}

func (s *benignThenBlockWriteSession) ReadPacket(_ []byte) (int, error) {
	return 0, net.ErrClosed
}

func (s *benignThenBlockWriteSession) WritePacket(_ []byte) ([]byte, error) {
	if s.writes.Add(1) == 1 {
		return nil, &quic.ApplicationError{ErrorCode: 0x100, Remote: true}
	}
	<-s.block
	return nil, nil
}

func (s *benignThenBlockWriteSession) Close() error { return nil }

func TestConnectIPTCPNetstackBenignTeardownFlushesOutboundQueue(t *testing.T) {
	sess := &benignThenBlockWriteSession{block: make(chan struct{})}
	stack, err := NewNetstack(context.Background(), sess, NetstackOptions{
		LocalIPv4: netip.MustParseAddr("198.18.0.2"),
		LocalIPv6: netip.MustParseAddr("fd00::2"),
	})
	if err != nil {
		t.Fatalf("create stack: %v", err)
	}
	defer stack.Close()

	payload := []byte{0x45, 0x00, 0x00, 0x28}
	stack.outboundOnce.Do(func() {
		stack.outboundCh = make(chan []byte, netstackOutboundQueueDepth)
	})
	const staleQueued = 8
	for i := 0; i < staleQueued; i++ {
		p := borrowOutboundBuf(len(payload))
		copy(p, payload)
		stack.outboundCh <- p
	}
	if depth := stack.OutboundQueueDepth(); depth != staleQueued {
		t.Fatalf("setup queue depth=%d want %d", depth, staleQueued)
	}

	done := make(chan struct{})
	go func() {
		_ = stack.DeliverOutboundPacket(payload)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("egress wedged after benign teardown with stale outbound queue")
	}
	if got := sess.writes.Load(); got != 1 {
		t.Fatalf("expected one WritePacket before flush, got %d", got)
	}
	if depth := stack.OutboundQueueDepth(); depth != 0 {
		t.Fatalf("outbound queue depth=%d want 0 after benign flush", depth)
	}
}

func TestConnectIPTCPNetstackWriteNotifyRetriesSameOutboundOnTransientWrite(t *testing.T) {
	sess := &retryableThenOKWriteSession{}
	sess.failRemaining.Store(5)
	stack, err := NewNetstack(context.Background(), sess, NetstackOptions{
		LocalIPv4: netip.MustParseAddr("198.18.0.2"),
		LocalIPv6: netip.MustParseAddr("fd00::2"),
	})
	if err != nil {
		t.Fatalf("create stack: %v", err)
	}
	defer stack.Close()

	payload := []byte{0x45, 0x00, 0x00, 0x28}
	if err := stack.DeliverOutboundPacket(payload); err != nil {
		t.Fatalf("deliver outbound: %v", err)
	}
	if got := sess.written.Load(); got != 1 {
		t.Fatalf("expected one successful write after retries, got %d", got)
	}
}

func newPacketPipePair() (*packetPipeSession, *packetPipeSession) {
	aToB := make(chan []byte, 256)
	bToA := make(chan []byte, 256)
	return &packetPipeSession{recvCh: bToA, sendCh: aToB, closeCh: make(chan struct{})},
		&packetPipeSession{recvCh: aToB, sendCh: bToA, closeCh: make(chan struct{})}
}

func (s *packetPipeSession) ReadPacket(buffer []byte) (int, error) {
	select {
	case <-s.closeCh:
		return 0, net.ErrClosed
	case packet, ok := <-s.recvCh:
		if !ok {
			return 0, io.EOF
		}
		if len(packet) > len(buffer) {
			return 0, io.ErrShortBuffer
		}
		return copy(buffer, packet), nil
	}
}

func (s *packetPipeSession) WritePacket(buffer []byte) ([]byte, error) {
	packet := append([]byte(nil), buffer...)
	select {
	case <-s.closeCh:
		return nil, net.ErrClosed
	case s.sendCh <- packet:
		return nil, nil
	}
}

func (s *packetPipeSession) Close() error {
	s.once.Do(func() {
		close(s.closeCh)
	})
	return nil
}

func runIngressRelay(sess PacketSession, ns *Netstack) func() {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		readBuffer := make([]byte, 64*1024)
		consecutiveRetryableFailures := 0
		const retryableReadFailureLimit = 32
		for {
			n, err := sess.ReadPacket(readBuffer)
			if err != nil {
				if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
					return
				}
				if IsRetryablePacketReadError(err) {
					consecutiveRetryableFailures++
					obsReadDropReason("retryable_read_error")
					if consecutiveRetryableFailures < retryableReadFailureLimit {
						time.Sleep(2 * time.Millisecond)
						continue
					}
					obsReadDropReason("retryable_read_exhausted")
					obsSessionReset("read_retry_exhausted")
				} else {
					obsReadDropReason("fatal_read_error")
					obsSessionReset("read_exit")
				}
				ns.FailWithError(errors.Join(Errs.Transport, err))
				return
			}
			consecutiveRetryableFailures = 0
			if n <= 0 {
				continue
			}
			ns.InjectInboundClone(readBuffer[:n])
		}
	}()
	return wg.Wait
}

func TestConnectIPTCPNetstackRecycleDialAfterBenign0x100(t *testing.T) {
	rawClient, serverSession := newPacketPipePair()
	clientSession := &benignOnceWriteSession{inner: rawClient}
	clientStack, err := NewNetstack(context.Background(), clientSession, NetstackOptions{
		LocalIPv4: netip.MustParseAddr("198.18.0.2"),
		LocalIPv6: netip.MustParseAddr("fd00::2"),
	})
	if err != nil {
		t.Fatalf("create client stack: %v", err)
	}

	serverStack, err := NewNetstack(context.Background(), serverSession, NetstackOptions{
		LocalIPv4: netip.MustParseAddr("198.18.0.1"),
		LocalIPv6: netip.MustParseAddr("fd00::1"),
	})
	if err != nil {
		t.Fatalf("create server stack: %v", err)
	}

	waitClientIngress := runIngressRelay(clientSession, clientStack)
	waitServerIngress := runIngressRelay(serverSession, serverStack)
	defer func() {
		_ = clientStack.Close()
		_ = serverStack.Close()
		_ = rawClient.Close()
		_ = serverSession.Close()
		waitClientIngress()
		waitServerIngress()
	}()

	serverAddr := netip.MustParseAddrPort("198.18.0.1:18081")
	listener, err := gonet.ListenTCP(serverStack.GStack(), tcpipFullAddress(serverAddr), ipv4Protocol(serverAddr))
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 256*1024)
				_, _ = io.CopyBuffer(io.Discard, c, buf)
			}(conn)
		}
	}()

	uploadCtx, uploadCancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	upConn, err := clientStack.DialContext(uploadCtx, socksaddrFromAddrPort(serverAddr))
	uploadCancel()
	if err != nil {
		t.Fatalf("dial upload: %v", err)
	}
	buf := make([]byte, 256*1024)
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		_, _ = upConn.Write(buf)
	}
	clientSession.ArmTeardown0x100()
	if err := upConn.Close(); err != nil {
		t.Fatalf("close upload conn: %v", err)
	}

	readyDeadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(readyDeadline) {
		clientStack.ScheduleOutboundDrain()
		if clientSession.fired.Load() {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !clientSession.fired.Load() {
		t.Fatal("expected one benign 0x100 during upload teardown drain")
	}

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer dialCancel()
	downConn, err := clientStack.DialContext(dialCtx, socksaddrFromAddrPort(serverAddr))
	if err != nil {
		t.Fatalf("dial after recycle: %v", err)
	}
	defer downConn.Close()
	if err := clientStack.TerminalError(); err != nil {
		t.Fatalf("unexpected terminal netstack error: %v", err)
	}
}

func TestConnectIPTCPNetstackDialBasic(t *testing.T) {
	clientSession, serverSession := newPacketPipePair()
	clientStack, err := NewNetstack(context.Background(), clientSession, NetstackOptions{
		LocalIPv4: netip.MustParseAddr("198.18.0.2"),
		LocalIPv6: netip.MustParseAddr("fd00::2"),
	})
	if err != nil {
		t.Fatalf("create client stack: %v", err)
	}

	serverStack, err := NewNetstack(context.Background(), serverSession, NetstackOptions{
		LocalIPv4: netip.MustParseAddr("198.18.0.1"),
		LocalIPv6: netip.MustParseAddr("fd00::1"),
	})
	if err != nil {
		t.Fatalf("create server stack: %v", err)
	}

	waitClientIngress := runIngressRelay(clientSession, clientStack)
	waitServerIngress := runIngressRelay(serverSession, serverStack)
	defer func() {
		_ = clientStack.Close()
		_ = serverStack.Close()
		_ = clientSession.Close()
		_ = serverSession.Close()
		waitClientIngress()
		waitServerIngress()
	}()

	serverAddr := netip.MustParseAddrPort("198.18.0.1:18080")
	listener, err := gonet.ListenTCP(serverStack.GStack(), tcpipFullAddress(serverAddr), ipv4Protocol(serverAddr))
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	defer listener.Close()

	acceptErrCh := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			acceptErrCh <- err
			return
		}
		defer conn.Close()
		buffer := make([]byte, 8)
		n, err := conn.Read(buffer)
		if err != nil {
			acceptErrCh <- err
			return
		}
		if string(buffer[:n]) != "ping" {
			acceptErrCh <- errors.New("unexpected payload")
			return
		}
		_, err = conn.Write([]byte("pong"))
		acceptErrCh <- err
	}()

	conn, err := clientStack.DialContext(context.Background(), socksaddrFromAddrPort(serverAddr))
	if err != nil {
		t.Fatalf("dial tcp over connect-ip: %v", err)
	}
	defer conn.Close()
	if _, err = conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	resp := make([]byte, 8)
	n, err := conn.Read(resp)
	if err != nil {
		t.Fatalf("read payload: %v", err)
	}
	if string(resp[:n]) != "pong" {
		t.Fatalf("unexpected response: %q", string(resp[:n]))
	}
	if err = <-acceptErrCh; err != nil {
		t.Fatalf("server flow failed: %v", err)
	}
}

func TestConnectIPTCPNetstackDialTimeout(t *testing.T) {
	clientSession, _ := newPacketPipePair()
	clientStack, err := NewNetstack(context.Background(), clientSession, NetstackOptions{
		LocalIPv4: netip.MustParseAddr("198.18.0.2"),
		LocalIPv6: netip.MustParseAddr("fd00::2"),
	})
	if err != nil {
		t.Fatalf("create client stack: %v", err)
	}
	defer clientStack.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()
	_, err = clientStack.DialContext(ctx, socksaddrFromAddrPort(netip.MustParseAddrPort("198.18.0.123:18081")))
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("expected context deadline exceeded, got: %v", err)
	}
}

func TestConnectIPTCPNetstackLifecycle(t *testing.T) {
	clientSession, _ := newPacketPipePair()
	clientStack, err := NewNetstack(context.Background(), clientSession, NetstackOptions{
		LocalIPv4: netip.MustParseAddr("198.18.0.2"),
		LocalIPv6: netip.MustParseAddr("fd00::2"),
	})
	if err != nil {
		t.Fatalf("create client stack: %v", err)
	}
	if err = clientStack.Close(); err != nil {
		t.Fatalf("close stack: %v", err)
	}
	_, err = clientStack.DialContext(context.Background(), socksaddrFromAddrPort(netip.MustParseAddrPort("198.18.0.1:443")))
	if !errors.Is(err, Errs.Closed) && !errors.Is(err, Errs.Transport) {
		t.Fatalf("expected lifecycle or transport closure error, got: %v", err)
	}
}

func TestConnectIPTCPNetstackRejectsNonIPDestination(t *testing.T) {
	clientSession, _ := newPacketPipePair()
	clientStack, err := NewNetstack(context.Background(), clientSession, NetstackOptions{
		LocalIPv4: netip.MustParseAddr("198.18.0.2"),
		LocalIPv6: netip.MustParseAddr("fd00::2"),
	})
	if err != nil {
		t.Fatalf("create client stack: %v", err)
	}
	defer clientStack.Close()

	_, err = clientStack.DialContext(context.Background(), M.Socksaddr{Fqdn: "example.com", Port: 443})
	if err == nil {
		t.Fatal("expected non-IP FQDN destination to be rejected")
	}
	if !errors.Is(err, Errs.DialRequiresIP) {
		t.Fatalf("expected Errs.DialRequiresIP, got: %v", err)
	}
}

func TestPrefixPreferredAddressRejectsUnspecified(t *testing.T) {
	if got := PrefixPreferredAddress(netip.MustParsePrefix("0.0.0.0/0")); got.IsValid() {
		t.Fatalf("expected invalid preferred address for IPv4 default route, got %s", got)
	}
	if got := PrefixPreferredAddress(netip.MustParsePrefix("::/0")); got.IsValid() {
		t.Fatalf("expected invalid preferred address for IPv6 default route, got %s", got)
	}
	if got := PrefixPreferredAddress(netip.MustParsePrefix("198.18.0.2/32")); !got.IsValid() || got.String() != "198.18.0.2" {
		t.Fatalf("expected host prefix address, got %v", got)
	}
}

func TestConnectIPTCPNetstackDialFailsAfterReadLoopError(t *testing.T) {
	sess := &failingReadSession{}
	stack, err := NewNetstack(context.Background(), sess, NetstackOptions{
		LocalIPv4: netip.MustParseAddr("198.18.0.2"),
		LocalIPv6: netip.MustParseAddr("fd00::2"),
	})
	if err != nil {
		t.Fatalf("create stack: %v", err)
	}
	waitIngress := runIngressRelay(sess, stack)
	defer func() {
		_ = stack.Close()
		waitIngress()
	}()

	time.Sleep(50 * time.Millisecond)
	_, dialErr := stack.DialContext(context.Background(), socksaddrFromAddrPort(netip.MustParseAddrPort("198.18.0.1:443")))
	if dialErr == nil {
		t.Fatal("expected dial error after packet-plane read failure in ingress feeder")
	}
	if !errors.Is(dialErr, Errs.Dial) {
		t.Fatalf("expected typed tcp dial error, got: %v", dialErr)
	}
}

func TestConnectIPTCPNetstackDialFailsAfterWriteNotifyFatalError(t *testing.T) {
	stack, err := NewNetstack(context.Background(), &fatalWriteSession{
		closeCh: make(chan struct{}),
	}, NetstackOptions{
		LocalIPv4: netip.MustParseAddr("198.18.0.2"),
		LocalIPv6: netip.MustParseAddr("fd00::2"),
	})
	if err != nil {
		t.Fatalf("create stack: %v", err)
	}
	defer stack.Close()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_, dialErr := stack.DialContext(context.Background(), socksaddrFromAddrPort(netip.MustParseAddrPort("198.18.0.1:443")))
		if dialErr != nil {
			if !errors.Is(dialErr, Errs.Dial) {
				t.Fatalf("expected typed tcp dial error, got: %v", dialErr)
			}
			if !errors.Is(dialErr, Errs.Transport) {
				t.Fatalf("expected transport cause after fatal write, got: %v", dialErr)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("expected dial to fail after fatal write-notify error")
}

func TestConnectIPNetstackLocalPrefixWaitForSession(t *testing.T) {
	t.Run("caps_long_env_when_profile_v4", func(t *testing.T) {
		t.Setenv("MASQUE_CONNECT_IP_TCP_NETSTACK_PREFIX_WAIT_SEC", "20")
		v4 := netip.MustParseAddr("172.16.0.2")
		if d := LocalPrefixWaitForSession(v4, netip.Addr{}); d != 2*time.Second {
			t.Fatalf("expected 2s cap, got %v", d)
		}
	})
	t.Run("caps_long_env_when_profile_v6", func(t *testing.T) {
		t.Setenv("MASQUE_CONNECT_IP_TCP_NETSTACK_PREFIX_WAIT_SEC", "20")
		v6 := netip.MustParseAddr("fd12::1")
		if d := LocalPrefixWaitForSession(netip.Addr{}, v6); d != 2*time.Second {
			t.Fatalf("expected 2s cap, got %v", d)
		}
	})
	t.Run("full_wait_without_profile", func(t *testing.T) {
		t.Setenv("MASQUE_CONNECT_IP_TCP_NETSTACK_PREFIX_WAIT_SEC", "9")
		if d := LocalPrefixWaitForSession(netip.Addr{}, netip.Addr{}); d != 9*time.Second {
			t.Fatalf("expected 9s from env, got %v", d)
		}
	})
	t.Run("respects_shorter_env_with_profile", func(t *testing.T) {
		t.Setenv("MASQUE_CONNECT_IP_TCP_NETSTACK_PREFIX_WAIT_SEC", "1")
		v4 := netip.MustParseAddr("172.16.0.2")
		if d := LocalPrefixWaitForSession(v4, netip.Addr{}); d != 1*time.Second {
			t.Fatalf("expected 1s (below cap), got %v", d)
		}
	})
}

func socksaddrFromAddrPort(addr netip.AddrPort) M.Socksaddr {
	return M.Socksaddr{Addr: addr.Addr(), Port: addr.Port()}
}

func tcpipFullAddress(addr netip.AddrPort) tcpip.FullAddress {
	return tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(addr.Addr().AsSlice()),
		Port: addr.Port(),
	}
}

func ipv4Protocol(addr netip.AddrPort) tcpip.NetworkProtocolNumber {
	if addr.Addr().Is4() {
		return ipv4.ProtocolNumber
	}
	return ipv6.ProtocolNumber
}
