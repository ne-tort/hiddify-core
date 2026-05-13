package masque

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

// fatalWriteSession blocks ReadPacket until Close; the first WritePacket returns a non-retryable error.
// This exercises the outbound path where WriteNotify calls failWithError and must still unblock readLoop + in-flight DialContext.
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

// runIngressRelay feeds ingress IP frames from a packet-plane session into the local
// CONNECT-IP userspace TCP stack. Production uses coreSession.connectIPIngressLoop; unit
// tests with packet pipes use this shim instead.
func runIngressRelay(sess IPPacketSession, ns *connectIPTCPNetstack) func() {
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
				if isRetryablePacketReadError(err) {
					consecutiveRetryableFailures++
					incConnectIPReadDropReason("retryable_read_error")
					if consecutiveRetryableFailures < retryableReadFailureLimit {
						time.Sleep(2 * time.Millisecond)
						continue
					}
					incConnectIPReadDropReason("retryable_read_exhausted")
					incConnectIPSessionReset("read_retry_exhausted")
				} else {
					incConnectIPReadDropReason("fatal_read_error")
					incConnectIPSessionReset("read_exit")
				}
				ns.failWithError(errors.Join(ErrTransportInit, err))
				return
			}
			consecutiveRetryableFailures = 0
			if n <= 0 {
				continue
			}
			ns.injectInboundClone(readBuffer[:n])
		}
	}()
	return wg.Wait
}

func TestConnectIPTCPNetstackDialBasic(t *testing.T) {
	clientSession, serverSession := newPacketPipePair()
	clientStack, err := newConnectIPTCPNetstack(context.Background(), clientSession, connectIPTCPNetstackOptions{
		LocalIPv4: netip.MustParseAddr("198.18.0.2"),
		LocalIPv6: netip.MustParseAddr("fd00::2"),
	})
	if err != nil {
		t.Fatalf("create client stack: %v", err)
	}

	serverStack, err := newConnectIPTCPNetstack(context.Background(), serverSession, connectIPTCPNetstackOptions{
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
	listener, err := gonet.ListenTCP(serverStack.gStack, tcpipFullAddress(serverAddr), ipv4Protocol(serverAddr))
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
	clientStack, err := newConnectIPTCPNetstack(context.Background(), clientSession, connectIPTCPNetstackOptions{
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
	clientStack, err := newConnectIPTCPNetstack(context.Background(), clientSession, connectIPTCPNetstackOptions{
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
	if !errors.Is(err, ErrLifecycleClosed) && !errors.Is(err, ErrTransportInit) {
		t.Fatalf("expected lifecycle or transport-init closure error, got: %v", err)
	}
}

func TestConnectIPTCPNetstackRejectsNonIPDestination(t *testing.T) {
	clientSession, _ := newPacketPipePair()
	clientStack, err := newConnectIPTCPNetstack(context.Background(), clientSession, connectIPTCPNetstackOptions{
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
	if !errors.Is(err, ErrTCPOverConnectIP) {
		t.Fatalf("expected ErrTCPOverConnectIP, got: %v", err)
	}
}

func TestPrefixPreferredAddressRejectsUnspecified(t *testing.T) {
	if got := prefixPreferredAddress(netip.MustParsePrefix("0.0.0.0/0")); got.IsValid() {
		t.Fatalf("expected invalid preferred address for IPv4 default route, got %s", got)
	}
	if got := prefixPreferredAddress(netip.MustParsePrefix("::/0")); got.IsValid() {
		t.Fatalf("expected invalid preferred address for IPv6 default route, got %s", got)
	}
	if got := prefixPreferredAddress(netip.MustParsePrefix("198.18.0.2/32")); !got.IsValid() || got.String() != "198.18.0.2" {
		t.Fatalf("expected host prefix address, got %v", got)
	}
}

func TestConnectIPTCPNetstackDialFailsAfterReadLoopError(t *testing.T) {
	sess := &failingReadSession{}
	stack, err := newConnectIPTCPNetstack(context.Background(), sess, connectIPTCPNetstackOptions{
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
	if !errors.Is(dialErr, ErrTCPDial) {
		t.Fatalf("expected typed tcp dial error, got: %v", dialErr)
	}
}

func TestConnectIPTCPNetstackDialFailsAfterWriteNotifyFatalError(t *testing.T) {
	stack, err := newConnectIPTCPNetstack(context.Background(), &fatalWriteSession{
		closeCh: make(chan struct{}),
	}, connectIPTCPNetstackOptions{
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
			if !errors.Is(dialErr, ErrTCPDial) {
				t.Fatalf("expected typed tcp dial error, got: %v", dialErr)
			}
			if !errors.Is(dialErr, ErrTransportInit) {
				t.Fatalf("expected transport-init cause after fatal write, got: %v", dialErr)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("expected dial to fail after fatal write-notify error")
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

func TestConnectIPNetstackLocalPrefixWaitForSession(t *testing.T) {
	t.Run("caps_long_env_when_profile_v4", func(t *testing.T) {
		t.Setenv("MASQUE_CONNECT_IP_TCP_NETSTACK_PREFIX_WAIT_SEC", "20")
		v4 := netip.MustParseAddr("172.16.0.2")
		if d := connectIPNetstackLocalPrefixWaitForSession(v4, netip.Addr{}); d != 2*time.Second {
			t.Fatalf("expected 2s cap, got %v", d)
		}
	})
	t.Run("caps_long_env_when_profile_v6", func(t *testing.T) {
		t.Setenv("MASQUE_CONNECT_IP_TCP_NETSTACK_PREFIX_WAIT_SEC", "20")
		v6 := netip.MustParseAddr("fd12::1")
		if d := connectIPNetstackLocalPrefixWaitForSession(netip.Addr{}, v6); d != 2*time.Second {
			t.Fatalf("expected 2s cap, got %v", d)
		}
	})
	t.Run("full_wait_without_profile", func(t *testing.T) {
		t.Setenv("MASQUE_CONNECT_IP_TCP_NETSTACK_PREFIX_WAIT_SEC", "9")
		if d := connectIPNetstackLocalPrefixWaitForSession(netip.Addr{}, netip.Addr{}); d != 9*time.Second {
			t.Fatalf("expected 9s from env, got %v", d)
		}
	})
	t.Run("respects_shorter_env_with_profile", func(t *testing.T) {
		t.Setenv("MASQUE_CONNECT_IP_TCP_NETSTACK_PREFIX_WAIT_SEC", "1")
		v4 := netip.MustParseAddr("172.16.0.2")
		if d := connectIPNetstackLocalPrefixWaitForSession(v4, netip.Addr{}); d != 1*time.Second {
			t.Fatalf("expected 1s (below cap), got %v", d)
		}
	})
}
