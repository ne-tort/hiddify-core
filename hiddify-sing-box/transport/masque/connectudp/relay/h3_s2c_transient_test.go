package relay

import (
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type flakyS2CSender struct {
	transientCalls atomic.Int32
	sends          atomic.Int32
	last           []byte
}

func (f *flakyS2CSender) SendDatagram(b []byte) error {
	if f.transientCalls.Load() > 0 {
		f.transientCalls.Add(-1)
		return syscall.EAGAIN
	}
	f.sends.Add(1)
	f.last = append([]byte(nil), b...)
	return nil
}

// TestProxyConnReceiveSurvivesTransientSendDatagram verifies S2C relay drops one payload
// under transient SendDatagram pressure but keeps the session alive (R2 masque-go parity).
func TestProxyConnReceiveSurvivesTransientSendDatagram(t *testing.T) {
	t.Parallel()

	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()

	conn, err := net.DialUDP("udp", nil, peer.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}

	sender := &flakyS2CSender{}
	sender.transientCalls.Store(1)

	done := make(chan error, 1)
	go func() {
		done <- proxyConnReceive(conn, sender)
	}()

	time.Sleep(20 * time.Millisecond)
	payload := []byte("s2c-transient-probe")
	if _, err := peer.WriteTo(payload, conn.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	if _, err := peer.WriteTo([]byte("s2c-ok"), conn.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	_ = conn.Close()
	_ = peer.Close()

	select {
	case err := <-done:
		if got := sender.sends.Load(); got < 1 {
			t.Fatalf("SendDatagram calls=%d want >=1 (err=%v)", got, err)
		}
		if err != nil && !isClosedUDPReadErr(err) {
			t.Fatalf("proxyConnReceive: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("proxyConnReceive did not finish")
	}
}

func isClosedUDPReadErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	return strings.Contains(err.Error(), "use of closed network connection")
}
