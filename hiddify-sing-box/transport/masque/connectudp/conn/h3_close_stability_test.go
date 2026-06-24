package conn

import (
	"context"
	"io"
	"net"
	"runtime"
	"runtime/pprof"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

type blockingH3Stream struct {
	recvGate  chan struct{}
	closed    atomic.Bool
	closeOnce sync.Once
}

func (s *blockingH3Stream) Read(p []byte) (int, error)  { return 0, io.EOF }
func (s *blockingH3Stream) Write(p []byte) (int, error) { return len(p), nil }

func (s *blockingH3Stream) Close() error {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		close(s.recvGate)
	})
	return nil
}

func (s *blockingH3Stream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case <-s.recvGate:
		if s.closed.Load() {
			return nil, net.ErrClosed
		}
	}
	return nil, net.ErrClosed
}

func (s *blockingH3Stream) SendDatagram([]byte) error { return nil }
func (s *blockingH3Stream) CancelRead(quic.StreamErrorCode) {}

func TestH3ConnCloseUnblocksBlockedReadFrom(t *testing.T) {
	trackH3ConnGoroutines(t)
	str := &blockingH3Stream{recvGate: make(chan struct{})}
	c := NewH3Conn(str, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})

	readErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 1500)
		_, _, err := c.ReadFrom(buf)
		readErr <- err
	}()

	time.Sleep(50 * time.Millisecond)

	closeDone := make(chan struct{})
	go func() {
		_ = c.Close()
		close(closeDone)
	}()

	select {
	case <-closeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("H3Conn.Close blocked >2s while ReadFrom waiting (selector interrupt contract)")
	}

	select {
	case err := <-readErr:
		if err != net.ErrClosed && err != io.EOF && err != context.Canceled {
			t.Fatalf("ReadFrom after Close: %v (want closed/canceled)", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReadFrom did not unblock after Close")
	}
}

func trackH3ConnGoroutines(t *testing.T) {
	t.Helper()
	runtime.GC()
	start := pprof.Lookup("goroutine").Count()
	t.Cleanup(func() {
		if t.Failed() {
			return
		}
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			runtime.GC()
			if pprof.Lookup("goroutine").Count() <= start {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		end := pprof.Lookup("goroutine").Count()
		if end > start {
			buf := make([]byte, 1<<20)
			n := runtime.Stack(buf, true)
			t.Fatalf("H3Conn goroutine leak: start=%d end=%d\n%s", start, end, buf[:n])
		}
	})
}