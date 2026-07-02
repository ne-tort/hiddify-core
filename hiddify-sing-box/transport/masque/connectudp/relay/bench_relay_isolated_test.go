package relay

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type countingDatagramSender struct {
	sent  atomic.Int64
	bytes atomic.Int64
}

func (m *countingDatagramSender) SendDatagram(b []byte) error {
	m.sent.Add(1)
	m.bytes.Add(int64(len(b)))
	return nil
}

func dialConnectedUDPPair(t *testing.T) (relay *net.UDPConn, inject net.PacketConn) {
	t.Helper()
	peer, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	relayConn, err := net.DialUDP("udp", nil, peer.LocalAddr().(*net.UDPAddr))
	if err != nil {
		_ = peer.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = relayConn.Close()
		_ = peer.Close()
	})
	return relayConn, peer
}

// TestRelayS2CIsolatedForwarding verifies server S2C relay without full MASQUE stack (UDP-6b1).
func TestRelayS2CIsolatedForwarding(t *testing.T) {
	t.Parallel()
	relayConn, peer := dialConnectedUDPPair(t)
	mock := &countingDatagramSender{}
	want := []byte("isolated-s2c")

	errCh := make(chan error, 1)
	go func() {
		errCh <- proxyConnReceive(context.Background(), relayConn, mock)
	}()

	if _, err := peer.WriteTo(want, relayConn.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for mock.sent.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if mock.sent.Load() != 1 {
		t.Fatalf("SendDatagram calls=%d want 1", mock.sent.Load())
	}
	_ = relayConn.Close()
	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, net.ErrClosed) && !strings.Contains(err.Error(), "closed") {
			t.Fatalf("proxyConnReceive: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("proxyConnReceive did not exit")
	}
}

// TestGATERelayS2CIsolatedMinMbps measures isolated server S2C goodput (M3-S1 attribution).
func TestGATERelayS2CIsolatedMinMbps(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	const (
		duration   = 2 * time.Second
		payloadLen = 512
		minMbps    = 100.0
	)

	relayConn, peer := dialConnectedUDPPair(t)
	mock := &countingDatagramSender{}
	payload := make([]byte, payloadLen)
	for i := range payload {
		payload[i] = byte(i)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = proxyConnReceive(context.Background(), relayConn, mock)
	}()

	stop := make(chan struct{})
	var writeErr atomic.Value
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := peer.WriteTo(payload, relayConn.LocalAddr()); err != nil {
				writeErr.Store(err)
				return
			}
		}
	}()

	time.Sleep(duration)
	close(stop)
	_ = relayConn.Close()
	wg.Wait()

	if err := writeErr.Load(); err != nil {
		t.Fatalf("sender write: %v", err)
	}
	rxBytes := mock.bytes.Load()
	mbps := float64(rxBytes) * 8 / duration.Seconds() / 1e6
	t.Logf("relay S2C isolated: rx_bytes=%d mbit/s=%.1f", rxBytes, mbps)
	if mbps < minMbps {
		t.Fatalf("isolated S2C %.1f Mbit/s < floor %.1f", mbps, minMbps)
	}
}
