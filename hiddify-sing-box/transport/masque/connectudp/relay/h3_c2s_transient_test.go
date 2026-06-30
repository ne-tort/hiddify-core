package relay

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type flakyC2SRecvStream struct {
	failRemaining atomic.Int32
	queue         [][]byte
}

func (f *flakyC2SRecvStream) ReceiveDatagram(context.Context) ([]byte, error) {
	if f.failRemaining.Load() > 0 {
		f.failRemaining.Add(-1)
		return nil, syscall.EAGAIN
	}
	if len(f.queue) == 0 {
		return nil, io.EOF
	}
	data := f.queue[0]
	f.queue = f.queue[1:]
	return data, nil
}

func (f *flakyC2SRecvStream) TryReceiveDatagram() ([]byte, bool) {
	return nil, false
}

// TestProxyConnSendSurvivesTransientReceiveDatagram verifies C2S relay keeps session alive
// under transient ReceiveDatagram pressure (R1 masque-go parity).
func TestProxyConnSendSurvivesTransientReceiveDatagram(t *testing.T) {
	t.Parallel()
	want := bytes.Repeat([]byte("probe"), 80)

	sink, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	conn, err := net.DialUDP("udp", nil, sink.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	payload := append([]byte{0}, want...)
	stream := &flakyC2SRecvStream{
		queue: [][]byte{payload},
	}
	stream.failRemaining.Store(4)

	done := make(chan error, 1)
	go func() {
		done <- (&Proxy{}).proxyConnSend(context.Background(), conn, stream)
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("proxyConnSend: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("proxyConnSend did not finish after transient retries")
	}

	buf := make([]byte, len(want)+64)
	n, _, err := sink.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], want) {
		t.Fatalf("onward UDP got %q want %q", buf[:n], want)
	}
}
