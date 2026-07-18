package relay

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

type scriptedC2SStream struct {
	mu    sync.Mutex
	queue [][]byte
	wake  chan struct{}
	eof   bool
}

func (s *scriptedC2SStream) enqueue(raw []byte) {
	s.mu.Lock()
	s.queue = append(s.queue, append([]byte(nil), raw...))
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *scriptedC2SStream) closeEOF() {
	s.mu.Lock()
	s.eof = true
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *scriptedC2SStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	for {
		s.mu.Lock()
		if len(s.queue) > 0 {
			raw := s.queue[0]
			s.queue = s.queue[1:]
			s.mu.Unlock()
			return raw, nil
		}
		if s.eof {
			s.mu.Unlock()
			return nil, io.EOF
		}
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.wake:
		}
	}
}

// TryReceiveDatagram implements h3quic.TryDrainHTTPDatagrams (non-blocking drain).
func (s *scriptedC2SStream) TryReceiveDatagram() ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.queue) == 0 {
		return nil, false
	}
	raw := s.queue[0]
	s.queue = s.queue[1:]
	return raw, true
}

type countingBatchWriter struct {
	mu        sync.Mutex
	writes    int // total payloads
	batchCalls int
	maxBatch  int
	failAfter int // fail when writes would exceed this (0 = always fail first)
	err       error
}

func (w *countingBatchWriter) writePayloadBatch(payloads [][]byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil && w.writes >= w.failAfter {
		return w.err
	}
	w.batchCalls++
	if n := len(payloads); n > w.maxBatch {
		w.maxBatch = n
	}
	w.writes += len(payloads)
	return nil
}

func ctx0Datagram(payload byte) []byte {
	raw := quic.AcquireMasqueDatagramRecvBuf(2)
	raw[0] = 0
	raw[1] = payload
	return raw
}

// TestH3C2SStatsOutOnlyAfterSuccessfulWrite covers AUDIT A1 / TASKS F0.1:
// c2s_in on accept; c2s_udp_out only after onward write; drop_udp_write on fail.
func TestH3C2SStatsOutOnlyAfterSuccessfulWrite(t *testing.T) {
	EnableRelayStatsForBench()
	t.Cleanup(func() {
		ResetUDPRelayStats()
	})

	t.Run("success_out_equals_in", func(t *testing.T) {
		ResetUDPRelayStats()
		str := &scriptedC2SStream{wake: make(chan struct{}, 4)}
		w := &countingBatchWriter{}
		str.enqueue(ctx0Datagram('a'))
		str.enqueue(ctx0Datagram('b'))
		str.closeEOF()

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := proxyConnSendWith(ctx, str, w); err != nil {
			t.Fatalf("proxyConnSendWith: %v", err)
		}
		snap := SnapshotUDPRelayStats()
		if snap.C2SDatagramIn != 2 {
			t.Fatalf("c2s_in=%d want 2", snap.C2SDatagramIn)
		}
		if snap.C2SUDPPayloadOut != 2 {
			t.Fatalf("c2s_udp_out=%d want 2", snap.C2SUDPPayloadOut)
		}
		if snap.C2SDropUDPWrite != 0 {
			t.Fatalf("c2s_drop_udp_write=%d want 0", snap.C2SDropUDPWrite)
		}
		if w.writes != 2 {
			t.Fatalf("writer writes=%d want 2", w.writes)
		}
	})

	t.Run("write_fail_in_without_out", func(t *testing.T) {
		ResetUDPRelayStats()
		str := &scriptedC2SStream{wake: make(chan struct{}, 4)}
		w := &countingBatchWriter{err: errors.New("onward write failed"), failAfter: 0}
		str.enqueue(ctx0Datagram('x'))
		str.closeEOF()

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		err := proxyConnSendWith(ctx, str, w)
		if err == nil {
			t.Fatal("expected onward write error")
		}
		snap := SnapshotUDPRelayStats()
		if snap.C2SDatagramIn != 1 {
			t.Fatalf("c2s_in=%d want 1", snap.C2SDatagramIn)
		}
		if snap.C2SUDPPayloadOut != 0 {
			t.Fatalf("c2s_udp_out=%d want 0 (must not count before successful write)", snap.C2SUDPPayloadOut)
		}
		if snap.C2SDropUDPWrite != 1 {
			t.Fatalf("c2s_drop_udp_write=%d want 1", snap.C2SDropUDPWrite)
		}
	})
}
