package quic

import (
	"testing"

	"github.com/quic-go/quic-go/internal/wire"
)

// TestDatagramQueueRecvRingFIFO locks conn-level recv ring dequeue (UDP-M9-02 adjunct).
func TestDatagramQueueRecvRingFIFO(t *testing.T) {
	q := newDatagramQueue(func() {}, nil)
	const n = 64
	for i := 0; i < n; i++ {
		q.HandleDatagramFrame(&wire.DatagramFrame{
			DataLenPresent: true,
			Data:           []byte{byte(i)},
		})
	}
	for i := 0; i < n; i++ {
		data, ok := q.TryReceive()
		if !ok {
			t.Fatalf("TryReceive %d: empty", i)
		}
		if data[0] != byte(i) {
			t.Fatalf("TryReceive %d: got %d", i, data[0])
		}
	}
}

// TestDatagramQueueSendLenTracksNoWakeBatch documents DatagramSendBacklog hook (UDP-M9-03 / 3de).
func TestDatagramQueueSendLenTracksNoWakeBatch(t *testing.T) {
	q := newDatagramQueue(func() {}, nil)
	frame := &wire.DatagramFrame{DataLenPresent: true, Data: []byte{0xab}}
	for range 8 {
		if err := q.AddNoWake(frame); err != nil {
			t.Fatal(err)
		}
	}
	if got := q.SendLen(); got != 8 {
		t.Fatalf("SendLen=%d want 8", got)
	}
	q.Pop()
	if got := q.SendLen(); got != 7 {
		t.Fatalf("SendLen after Pop=%d want 7", got)
	}
}
