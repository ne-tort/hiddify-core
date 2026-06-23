package masque

import (
	"net"
	"sync/atomic"
	"syscall"
	"testing"
)

type flakyUDPConn struct {
	*net.UDPConn
	failRemaining atomic.Int32
}

func (f *flakyUDPConn) Write(b []byte) (int, error) {
	if f.failRemaining.Load() > 0 {
		f.failRemaining.Add(-1)
		return 0, syscall.EAGAIN
	}
	return f.UDPConn.Write(b)
}

func TestUDPDatagramWriterRetriesTransientBeforeDrop(t *testing.T) {
	sink, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("sink: %v", err)
	}
	defer sink.Close()

	conn, err := net.DialUDP("udp", nil, sink.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	tuneUDPSocketBuffers(conn)

	flaky := &flakyUDPConn{UDPConn: conn}
	flaky.failRemaining.Store(3)

	before := TransientUDPSendDropTotal()
	w := newUDPDatagramWriter(conn)
	w.writeConn = flaky
	payload := []byte("probe-payload")
	ok, fatal := w.writePayloadWithRetry(payload)
	if fatal != nil {
		t.Fatalf("write: %v", fatal)
	}
	if !ok {
		t.Fatal("expected success after transient retries")
	}
	if got := TransientUDPSendDropTotal(); got != before {
		t.Fatalf("transient drop total %d -> %d, want no drop after retries", before, got)
	}
	buf := make([]byte, 64)
	n, _, err := sink.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("sink read: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("sink got %d bytes want %d", n, len(payload))
	}
}

func TestUDPDatagramWriterDropAfterRetryExhausted(t *testing.T) {
	sink, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("sink: %v", err)
	}
	defer sink.Close()

	conn, err := net.DialUDP("udp", nil, sink.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	flaky := &flakyUDPConn{UDPConn: conn}
	flaky.failRemaining.Store(1000)

	before := TransientUDPSendDropTotal()
	w := newUDPDatagramWriter(conn)
	w.writeConn = flaky
	ok, fatal := w.writePayloadWithRetry([]byte("x"))
	if fatal != nil {
		t.Fatalf("unexpected fatal: %v", fatal)
	}
	if ok {
		t.Fatal("expected drop after retry exhaustion")
	}
	if got := TransientUDPSendDropTotal(); got <= before {
		t.Fatalf("drop total should increase: before=%d after=%d", before, got)
	}
}
