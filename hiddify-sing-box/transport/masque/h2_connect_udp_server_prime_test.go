package masque

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go/quicvarint"
)

// TestServeH2ConnectUDPEmptyUplinkPrimeDoesNotWriteUDP verifies stream-prime zero-length
// DATAGRAM capsules unblock the downlink without writing to the onward UDP socket.
func TestServeH2ConnectUDPEmptyUplinkPrimeDoesNotWriteUDP(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("connected UDP ICMP behavior differs on Windows")
	}
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tcpLn.Close() })
	tcpPort := tcpLn.Addr().(*net.TCPAddr).Port

	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(tcpPort)))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	var uplink bytes.Buffer
	if err := writeUDPH2ConnectDatagramCapsule(&uplink, nil); err != nil {
		t.Fatal(err)
	}

	w := &recordingH2UDPResponseWriter{ResponseWriter: &nopH2UDPResponseWriter{}}
	r := &http.Request{
		Method: http.MethodConnect,
		Body:   io.NopCloser(bytes.NewReader(uplink.Bytes())),
	}
	done := make(chan error, 1)
	go func() { done <- ServeH2ConnectUDP(w, r, conn) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ServeH2ConnectUDP: %v", err)
		}
	case <-time.After(2 * time.Second):
		// Relay may block waiting for UDP; prime must have started downlink without write error.
	}
	if w.datagramCapsules() == 0 {
		t.Fatal("expected at least one downlink DATAGRAM capsule (ICMP empty or payload) after prime")
	}
}

type nopH2UDPResponseWriter struct{}

func (nopH2UDPResponseWriter) Header() http.Header         { return http.Header{} }
func (nopH2UDPResponseWriter) Write(p []byte) (int, error) { return len(p), nil }
func (nopH2UDPResponseWriter) WriteHeader(int)             {}

type recordingH2UDPResponseWriter struct {
	http.ResponseWriter
	mu   sync.Mutex
	wire bytes.Buffer
}

func (w *recordingH2UDPResponseWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	w.wire.Write(p)
	w.mu.Unlock()
	return len(p), nil
}

func (w *recordingH2UDPResponseWriter) datagramCapsules() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := 0
	r := quicvarint.NewReader(bytes.NewReader(w.wire.Bytes()))
	for {
		ct, cr, err := parseH2ConnectUDPCapsule(r)
		if err != nil {
			if err == io.EOF {
				break
			}
			return n
		}
		if ct == capsuleTypeDatagram {
			n++
		}
		_, _ = io.Copy(io.Discard, cr)
	}
	return n
}
