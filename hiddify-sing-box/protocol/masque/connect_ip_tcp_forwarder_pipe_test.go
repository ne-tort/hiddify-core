package masque

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/masque/server"
	cip "github.com/sagernet/sing-box/transport/masque/connectip"
	fwd "github.com/sagernet/sing-box/transport/masque/forwarder"
	M "github.com/sagernet/sing/common/metadata"
)

// TestConnectIPTCPForwarderPipeE2E exercises server.RouteConnectIPBlocked + S2 forwarder over a
// packet pipe (no quic-go / docker). Client uses connectip.Netstack; server dials host TCP.
func TestConnectIPTCPForwarderPipeE2E(t *testing.T) {
	t.Parallel()

	clientSess, serverSess := newMasquePacketPipePair()
	peer := netip.MustParsePrefix("198.18.0.2/32")

	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { _ = echoLn.Close() })
	echoPort := uint16(echoLn.Addr().(*net.TCPAddr).Port)
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 64)
				n, err := c.Read(buf)
				if err != nil || n == 0 {
					return
				}
				_, _ = c.Write(buf[:n])
			}(c)
		}
	}()

	clientNS, err := cip.NewNetstack(context.Background(), clientSess, cip.NetstackOptions{
		LocalIPv4: netip.MustParseAddr("198.18.0.2"),
		MTU:       1372,
	})
	if err != nil {
		t.Fatalf("client netstack: %v", err)
	}
	waitIngress := runMasquePipeIngressRelay(clientSess, clientNS)

	packetConn := server.NewConnectIPNetPacketConn(&pipePacketPlaneConn{
		session:      serverSess,
		peerPrefixes: []netip.Prefix{peer},
	})

	routeCtx, routeCancel := context.WithCancel(context.Background())
	routeDone := make(chan struct{})
	go func() {
		defer close(routeDone)
		server.RouteConnectIPBlocked(nil, routeCtx, packetConn, adapter.InboundContext{}, nil, option.MasqueEndpointOptions{
			AllowPrivateTargets: true,
		}, net.Dialer{})
	}()

	t.Cleanup(func() {
		routeCancel()
		_ = clientNS.Close()
		_ = clientSess.Close()
		_ = serverSess.Close()
		waitIngress()
		select {
		case <-routeDone:
		case <-time.After(3 * time.Second):
			t.Log("server.RouteConnectIPBlocked did not exit promptly after cleanup")
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	conn, err := clientNS.DialContext(ctx, M.ParseSocksaddrHostPort("127.0.0.1", echoPort))
	if err != nil {
		t.Fatalf("dial tcp over connect-ip pipe: %v", err)
	}
	defer conn.Close()

	msg := []byte("connect-ip-server-pipe")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	reply := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(reply, msg) {
		t.Fatalf("echo mismatch: got %q want %q", reply, msg)
	}
}

type pipePacketPlaneConn struct {
	session      *masquePacketPipeSession
	peerPrefixes []netip.Prefix
}

func (c *pipePacketPlaneConn) ReadPacket(b []byte) (int, error) {
	return c.session.ReadPacket(b)
}

func (c *pipePacketPlaneConn) WritePacket(b []byte) ([]byte, error) {
	return c.session.WritePacket(b)
}

func (c *pipePacketPlaneConn) Close() error {
	return c.session.Close()
}

func (c *pipePacketPlaneConn) CurrentPeerPrefixes() []netip.Prefix {
	return c.peerPrefixes
}

var _ fwd.PacketPlaneConn = (*pipePacketPlaneConn)(nil)

type masquePacketPipeSession struct {
	recvCh  chan []byte
	sendCh  chan []byte
	closeCh chan struct{}
	once    sync.Once
}

func newMasquePacketPipePair() (*masquePacketPipeSession, *masquePacketPipeSession) {
	aToB := make(chan []byte, 256)
	bToA := make(chan []byte, 256)
	return &masquePacketPipeSession{recvCh: bToA, sendCh: aToB, closeCh: make(chan struct{})},
		&masquePacketPipeSession{recvCh: aToB, sendCh: bToA, closeCh: make(chan struct{})}
}

func (s *masquePacketPipeSession) ReadPacket(buffer []byte) (int, error) {
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

func (s *masquePacketPipeSession) WritePacket(buffer []byte) ([]byte, error) {
	packet := append([]byte(nil), buffer...)
	select {
	case <-s.closeCh:
		return nil, net.ErrClosed
	case s.sendCh <- packet:
		return nil, nil
	}
}

func (s *masquePacketPipeSession) Close() error {
	s.once.Do(func() {
		close(s.closeCh)
	})
	return nil
}

func runMasquePipeIngressRelay(sess *masquePacketPipeSession, ns *cip.Netstack) func() {
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
				if cip.IsRetryablePacketReadError(err) {
					consecutiveRetryableFailures++
					if consecutiveRetryableFailures < retryableReadFailureLimit {
						time.Sleep(2 * time.Millisecond)
						continue
					}
				}
				ns.FailWithError(errors.Join(cip.Errs.Transport, err))
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
