package relay

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type recordingDatagramSender struct {
	sends atomic.Int64
	last  []byte
}

func (r *recordingDatagramSender) SendDatagram(b []byte) error {
	r.sends.Add(1)
	r.last = append([]byte(nil), b...)
	return nil
}

// TestProxyConnReceiveUsesSyncSendDatagram locks prod server S2C path (UDP-M3-03 CUT — no NoWake batch).
func TestProxyConnReceiveUsesSyncSendDatagram(t *testing.T) {
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

	sender := &recordingDatagramSender{}
	errCh := make(chan error, 1)
	go func() {
		errCh <- proxyConnReceive(context.Background(), conn, sender)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for sender.sends.Load() == 0 && time.Now().Before(deadline) {
		if _, err := peer.WriteTo([]byte("relay-guard"), conn.LocalAddr()); err != nil {
			t.Fatal(err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	_ = conn.Close()
	_ = peer.Close()

	select {
	case err := <-errCh:
		if err != nil && sender.sends.Load() == 0 {
			t.Fatalf("proxyConnReceive: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("proxyConnReceive did not finish")
	}
	if got := sender.sends.Load(); got < 1 {
		t.Fatalf("SendDatagram calls=%d want >=1", got)
	}
	if len(sender.last) < 2 || sender.last[0] != 0x00 {
		t.Fatalf("want ctx0-prefixed datagram, got %v", sender.last)
	}
}

// TestTuneMasqueUDPSocketBuffers4MiB documents M5-01 prod socket tune (relay onward UDP).
func TestTuneMasqueUDPSocketBuffers4MiB(t *testing.T) {
	var c mockBufferConn
	TuneMasqueUDPSocketBuffers(&c)
	const want = masqueUDPSocketBufferBytes
	if c.readBuf != want || c.writeBuf != want {
		t.Fatalf("buffers read=%d write=%d want %d", c.readBuf, c.writeBuf, want)
	}
}

type mockBufferConn struct {
	readBuf, writeBuf int
}

func (m *mockBufferConn) SetReadBuffer(n int) error {
	m.readBuf = n
	return nil
}

func (m *mockBufferConn) SetWriteBuffer(n int) error {
	m.writeBuf = n
	return nil
}
