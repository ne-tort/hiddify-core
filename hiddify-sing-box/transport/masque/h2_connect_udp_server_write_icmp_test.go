package masque

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
)

// TestServeH2ConnectUDPWriteRefusedRelaysEmptyDatagram verifies ICMP port-unreachable surfaced on
// connected-UDP Write (Linux bench dig to TCP-only port) is relayed as an empty RFC 9297 DATAGRAM.
func TestServeH2ConnectUDPWriteRefusedRelaysEmptyDatagram(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("connected UDP ICMP on Write is unreliable on Windows")
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
	if err := http3.WriteCapsule(&uplink, capsuleTypeDatagram, []byte{0, 0xde, 0xad}); err != nil {
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
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not finish after uplink write to refused port")
	}
	if w.datagramCapsules() < 1 {
		t.Fatal("expected empty ICMP DATAGRAM capsule on response body after Write ECONNREFUSED")
	}
}
