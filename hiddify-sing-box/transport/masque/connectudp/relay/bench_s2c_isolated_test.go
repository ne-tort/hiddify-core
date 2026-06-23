package relay

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type mockDatagramSender struct {
	bytes atomic.Uint64
}

func (m *mockDatagramSender) SendDatagram(data []byte) error {
	m.bytes.Add(uint64(len(data)))
	return nil
}

func isClosedUDPRead(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
		return true
	}
	var op *net.OpError
	return errors.As(err, &op) && op.Err != nil && op.Err.Error() == "use of closed network connection"
}

// TestBenchS2CRelayIsolated attributes UDP→HTTP/3 SendDatagram on the server relay path only (masque-go shape).
func TestBenchS2CRelayIsolated(t *testing.T) {
	const benchDur = 500 * time.Millisecond
	payload := make([]byte, 512)

	sink, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("sink: %v", err)
	}
	defer sink.Close()

	relayConn, err := net.DialUDP("udp", nil, sink.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial sink: %v", err)
	}
	tuneMasqueUDPSocketBuffers(relayConn)

	stop := make(chan struct{})
	var writerWG sync.WaitGroup
	relayAddr := relayConn.LocalAddr().(*net.UDPAddr)
	writerWG.Add(1)
	go func() {
		defer writerWG.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := sink.WriteToUDP(payload, relayAddr); err != nil {
				return
			}
		}
	}()

	mock := &mockDatagramSender{}
	recvDone := make(chan error, 1)
	go func() {
		recvDone <- proxyConnReceive(relayConn, mock)
	}()

	time.Sleep(benchDur)
	close(stop)
	_ = relayConn.Close()
	writerWG.Wait()
	recvErr := <-recvDone
	if recvErr != nil && !isClosedUDPRead(recvErr) {
		t.Fatalf("proxyConnReceive: %v", recvErr)
	}

	bytes := mock.bytes.Load()
	mbps := float64(bytes*8) / benchDur.Seconds() / 1e6
	t.Logf("BENCH relay S2C isolated (sync SendDatagram): %.1f Mbit/s (%d bytes)", mbps, bytes)
}
