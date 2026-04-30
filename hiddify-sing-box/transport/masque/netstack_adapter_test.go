package masque

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
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

func (s *packetPipeSession) WritePacket(buffer []byte) error {
	packet := append([]byte(nil), buffer...)
	select {
	case <-s.closeCh:
		return net.ErrClosed
	case s.sendCh <- packet:
		return nil
	}
}

func (s *packetPipeSession) Close() error {
	s.once.Do(func() {
		close(s.closeCh)
	})
	return nil
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
	defer clientStack.Close()

	serverStack, err := newConnectIPTCPNetstack(context.Background(), serverSession, connectIPTCPNetstackOptions{
		LocalIPv4: netip.MustParseAddr("198.18.0.1"),
		LocalIPv6: netip.MustParseAddr("fd00::1"),
	})
	if err != nil {
		t.Fatalf("create server stack: %v", err)
	}
	defer serverStack.Close()

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
	if !errors.Is(err, ErrLifecycleClosed) {
		t.Fatalf("expected lifecycle closed error, got: %v", err)
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
