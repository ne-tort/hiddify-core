package quic

import (
	"testing"

	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/quicvarint"
)

func TestMasqueDatagramFrameHasTCPPayload(t *testing.T) {
	dataPkt := masqueTestIPv4TCPPacket(t, true)
	ackPkt := masqueTestIPv4TCPPacket(t, false)

	dataFrame := masqueTestProxiedIPDatagramFrame(t, dataPkt)
	ackFrame := masqueTestProxiedIPDatagramFrame(t, ackPkt)

	if !masqueDatagramFrameHasTCPPayload(dataFrame) {
		t.Fatal("expected TCP payload frame")
	}
	if masqueDatagramFrameHasTCPPayload(ackFrame) {
		t.Fatal("expected pure ACK frame")
	}
}

func TestDatagramQueuePrefersTCPPayload(t *testing.T) {
	q := newDatagramQueue(func() {}, nil)
	ack := masqueTestProxiedIPDatagramFrame(t, masqueTestIPv4TCPPacket(t, false))
	data := masqueTestProxiedIPDatagramFrame(t, masqueTestIPv4TCPPacket(t, true))
	for range 8 {
		if err := q.AddNoWake(ack); err != nil {
			t.Fatalf("enqueue ack: %v", err)
		}
	}
	if err := q.AddNoWake(data); err != nil {
		t.Fatalf("enqueue data: %v", err)
	}
	if peek := q.Peek(); peek != data {
		t.Fatal("Peek must prefer TCP DATA over queued ACKs")
	}
	q.Pop()
}

func masqueTestProxiedIPDatagramFrame(t *testing.T, ip []byte) *wire.DatagramFrame {
	t.Helper()
	payload := quicvarint.Append(nil, uint64(1))
	payload = append(payload, 0x00) // default CONNECT-IP context ID
	payload = append(payload, ip...)
	return &wire.DatagramFrame{DataLenPresent: true, Data: payload}
}

func masqueTestIPv4TCPPacket(t *testing.T, withPayload bool) []byte {
	t.Helper()
	const (
		ihl  = 20
		doff = 20
	)
	total := ihl + doff
	if withPayload {
		total += 100
	}
	pkt := make([]byte, total)
	pkt[0] = 0x45
	pkt[9] = 6
	pkt[12] = 0x50 // data offset 5
	if withPayload {
		for i := ihl + doff; i < total; i++ {
			pkt[i] = 0xAB
		}
	}
	return pkt
}
