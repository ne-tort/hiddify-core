package http3

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func newTestStateTrackingStream() *stateTrackingStream {
	return &stateTrackingStream{hasData: make(chan struct{}, 1)}
}

// TestStateTrackingStreamRingFIFO locks O(1) ring dequeue order (UDP-M3-07 / UDP-M9-02).
func TestStateTrackingStreamRingFIFO(t *testing.T) {
	s := newTestStateTrackingStream()
	const n = 128
	for i := 0; i < n; i++ {
		buf := quic.AcquireMasqueDatagramRecvBuf(1)
		buf[0] = byte(i)
		if !s.enqueueDatagramOwned(buf) {
			t.Fatalf("enqueue %d failed", i)
		}
	}
	for i := 0; i < n; i++ {
		data, ok := s.TryReceiveDatagram()
		if !ok {
			t.Fatalf("dequeue %d: empty", i)
		}
		if data[0] != byte(i) {
			t.Fatalf("dequeue %d: got %d", i, data[0])
		}
		quic.ReleaseMasqueDatagramReceiveBuffer(data)
	}
}

// TestStateTrackingStreamRingWrapAround verifies head/tail modulo without slice shift.
func TestStateTrackingStreamRingWrapAround(t *testing.T) {
	s := newTestStateTrackingStream()
	for i := 0; i < 10; i++ {
		buf := quic.AcquireMasqueDatagramRecvBuf(1)
		buf[0] = byte(i)
		if !s.enqueueDatagramOwned(buf) {
			t.Fatalf("enqueue %d", i)
		}
	}
	for i := 0; i < 7; i++ {
		data, ok := s.TryReceiveDatagram()
		if !ok || data[0] != byte(i) {
			t.Fatalf("first drain %d: ok=%v", i, ok)
		}
		quic.ReleaseMasqueDatagramReceiveBuffer(data)
	}
	for i := 10; i < 15; i++ {
		buf := quic.AcquireMasqueDatagramRecvBuf(1)
		buf[0] = byte(i)
		if !s.enqueueDatagramOwned(buf) {
			t.Fatalf("re-enqueue %d", i)
		}
	}
	want := []byte{7, 8, 9, 10, 11, 12, 13, 14}
	for i, w := range want {
		data, ok := s.TryReceiveDatagram()
		if !ok || data[0] != w {
			t.Fatalf("wrap dequeue %d: ok=%v got=%v want=%d", i, ok, data, w)
		}
		quic.ReleaseMasqueDatagramReceiveBuffer(data)
	}
}

// TestStateTrackingStreamRingDropWhenFull documents silent drop at streamDatagramQueueLen.
func TestStateTrackingStreamRingDropWhenFull(t *testing.T) {
	s := newTestStateTrackingStream()
	s.queue = make([][]byte, streamDatagramQueueLen)
	s.queueCount = streamDatagramQueueLen
	before := StreamDatagramQueueDropTotal()
	buf := quic.AcquireMasqueDatagramRecvBuf(1)
	if s.enqueueDatagramOwned(buf) {
		t.Fatal("expected drop when stream queue full")
	}
	if got := StreamDatagramQueueDropTotal(); got != before+1 {
		t.Fatalf("drop counter: got %d want %d", got, before+1)
	}
}

// TestStateTrackingStreamSplitLockConcurrentSendRecv documents sendMx/recvMx independence (UDP-M4-03 / 3bd).
func TestStateTrackingStreamSplitLockConcurrentSendRecv(t *testing.T) {
	var sends atomic.Int64
	s := &stateTrackingStream{
		hasData: make(chan struct{}, 1),
		sendDatagram: func([]byte) error {
			sends.Add(1)
			return nil
		},
	}
	const (
		workers = 16
		rounds  = 200
	)
	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			for j := range rounds {
				_ = s.SendDatagram([]byte{1})
				buf := quic.AcquireMasqueDatagramRecvBuf(1)
				buf[0] = byte(j)
				if !s.enqueueDatagramOwned(buf) {
					quic.ReleaseMasqueDatagramReceiveBuffer(buf)
				}
				_, _ = s.TryReceiveDatagram()
			}
		}()
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("split-lock concurrent send/recv deadlocked")
	}
	if sends.Load() == 0 {
		t.Fatal("expected SendDatagram traffic under concurrent recv")
	}
}
