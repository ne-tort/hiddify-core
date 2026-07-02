package relay

import (
	"context"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/sagernet/sing-box/transport/masque/connectudp/frame"
)

type cancelAfterDatagramStream struct {
	mu    sync.Mutex
	queue [][]byte
	wake  chan struct{}
}

func (s *cancelAfterDatagramStream) enqueue(raw []byte) {
	s.mu.Lock()
	s.queue = append(s.queue, append([]byte(nil), raw...))
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *cancelAfterDatagramStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	for {
		s.mu.Lock()
		if len(s.queue) > 0 {
			raw := s.queue[0]
			s.queue = s.queue[1:]
			s.mu.Unlock()
			return raw, nil
		}
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.wake:
		}
	}
}

// TestProxyConnSendFlushesTailBatchOnRelayCancel verifies Linux min-batch defer does not drop
// payloads when relay context is cancelled before EOF (client disconnect / skip-goroutine cancel).
func TestProxyConnSendFlushesTailBatchOnRelayCancel(t *testing.T) {
	if runtime.GOOS != "linux" || h3C2SUDPFlushMinBatchLinux <= 1 {
		t.Skip("partial C2S batch defer requires linux min batch > 1")
	}

	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()

	conn, err := net.DialUDP("udp", nil, peer.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	const pktCount = h3C2SUDPFlushMinBatchLinux - 1
	if pktCount <= 0 {
		t.Fatal("need partial batch size")
	}

	str := &cancelAfterDatagramStream{wake: make(chan struct{}, pktCount+1)}
	for i := 0; i < pktCount; i++ {
		raw := quic.AcquireMasqueDatagramRecvBuf(2)
		raw[0] = 0
		raw[1] = byte('a' + i)
		str.enqueue(raw)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- (&Proxy{}).proxyConnSend(ctx, conn, str)
	}()

	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected context cancel error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("proxyConnSend did not exit after cancel")
	}

	buf := make([]byte, 64)
	rx := 0
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	for {
		n, _, err := peer.ReadFrom(buf)
		if err != nil {
			break
		}
		if n > 0 {
			rx++
		}
	}
	if rx != pktCount {
		t.Fatalf("onward rx=%d want %d (tail batch must flush on relay cancel)", rx, pktCount)
	}
}

type eofWhenEmptyStream struct {
	mu    sync.Mutex
	queue [][]byte
}

func (s *eofWhenEmptyStream) ReceiveDatagram(context.Context) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.queue) == 0 {
		return nil, io.EOF
	}
	raw := s.queue[0]
	s.queue = s.queue[1:]
	return raw, nil
}

func TestProxyConnSendFlushesTailBatchOnEOF(t *testing.T) {
	if runtime.GOOS != "linux" || h3C2SUDPFlushMinBatchLinux <= 1 {
		t.Skip("partial C2S batch defer requires linux min batch > 1")
	}

	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()

	conn, err := net.DialUDP("udp", nil, peer.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	const pktCount = h3C2SUDPFlushMinBatchLinux - 1
	str := &eofWhenEmptyStream{}
	for i := 0; i < pktCount; i++ {
		str.queue = append(str.queue, append([]byte{frame.ContextIDZeroWire[0]}, byte('z'+i)))
	}

	ctx := context.Background()
	if err := (&Proxy{}).proxyConnSend(ctx, conn, str); err != nil {
		t.Fatalf("proxyConnSend: %v", err)
	}

	buf := make([]byte, 64)
	rx := 0
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	for {
		n, _, err := peer.ReadFrom(buf)
		if err != nil {
			break
		}
		if n > 0 {
			rx++
		}
	}
	if rx != pktCount {
		t.Fatalf("onward rx=%d want %d on EOF exit", rx, pktCount)
	}
}
