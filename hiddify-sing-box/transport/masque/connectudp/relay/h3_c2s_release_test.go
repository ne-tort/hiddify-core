package relay

import (
	"bytes"
	"net"
	"testing"

	"github.com/quic-go/quic-go"
	"github.com/sagernet/sing-box/transport/masque/connectudp/frame"
)

// TestMasqueDatagramReleaseBeforeWriteCorruptsSubslice proves ParseHTTPDatagramUDP returns
// a view into the pooled recv buffer; Release before conn.Write allows pool reuse to stomp payload.
func TestMasqueDatagramReleaseBeforeWriteCorruptsSubslice(t *testing.T) {
	t.Parallel()
	want := bytes.Repeat([]byte("A"), 512)

	var sawCorruption bool
	for i := 0; i < 512; i++ {
		data := quic.AcquireMasqueDatagramRecvBuf(1 + len(want))
		data[0] = 0
		copy(data[1:], want)

		udpPayload, ok, err := frame.ParseHTTPDatagramUDP(data)
		if err != nil || !ok {
			t.Fatalf("parse: err=%v ok=%v", err, ok)
		}
		if !bytes.Equal(udpPayload, want) {
			t.Fatal("payload mismatch before release")
		}

		// Anti-pattern (old relay/h3.go forwardC2SDatagram): release parent before consumer finishes.
		quic.ReleaseMasqueDatagramReceiveBuffer(data)

		stomper := quic.AcquireMasqueDatagramRecvBuf(len(want) + 1)
		for j := range stomper {
			stomper[j] = 0xFF
		}
		quic.ReleaseMasqueDatagramReceiveBuffer(stomper)

		if !bytes.Equal(udpPayload, want) {
			sawCorruption = true
			break
		}
	}
	if !sawCorruption {
		t.Fatal("expected subsliсe corruption after Release-before-use under pool churn (512 tries)")
	}
}

// TestRelayC2SForwardReleaseAfterWrite preserves payload written to onward UDP (correct order).
func TestRelayC2SForwardReleaseAfterWrite(t *testing.T) {
	t.Parallel()
	want := bytes.Repeat([]byte("B"), 400)

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

	data := quic.AcquireMasqueDatagramRecvBuf(1 + len(want))
	data[0] = 0
	copy(data[1:], want)

	udpPayload, ok, err := frame.ParseHTTPDatagramUDP(data)
	if err != nil || !ok {
		t.Fatalf("parse: err=%v ok=%v", err, ok)
	}
	if _, err := conn.Write(udpPayload); err != nil {
		t.Fatal(err)
	}
	quic.ReleaseMasqueDatagramReceiveBuffer(data)

	buf := make([]byte, len(want)+64)
	n, addr, err := peer.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], want) {
		t.Fatalf("onward UDP got %d bytes from %v, want %q prefix", n, addr, want[:16])
	}
}
