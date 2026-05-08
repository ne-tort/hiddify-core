package http3

import (
	"context"
	"errors"
	"os"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/quic-go/quic-go"
)

// streamDatagramQueueDropTotal counts DATAGRAM frames dropped because the per-stream
// backlog reached streamDatagramQueueLen (enqueueDatagram silent drop).
var streamDatagramQueueDropTotal atomic.Uint64

// StreamDatagramQueueDropTotal returns enqueueDatagram drops due to a full per-stream queue (process-wide).
func StreamDatagramQueueDropTotal() uint64 {
	return streamDatagramQueueDropTotal.Load()
}

// streamDatagramRecvClosedDropTotal counts DATAGRAM frames dropped because ReceiveDatagram
// side already failed/closed (enqueueDatagram silent drop).
var streamDatagramRecvClosedDropTotal atomic.Uint64

// StreamDatagramRecvClosedDropTotal returns enqueueDatagram drops after recv-side close (process-wide).
func StreamDatagramRecvClosedDropTotal() uint64 {
	return streamDatagramRecvClosedDropTotal.Load()
}

// Default per-stream backlog was raised from 4096 after CONNECT-IP degrade_matrix triage showed
// sink-side datagram gaps at high shaped rates without QUIC rcv-queue or packer oversize signals,
// consistent with transient HTTP/3 per-stream enqueue outpacing application drain.
const defaultStreamDatagramQueueLen = 8192

// Per-stream HTTP/3 DATAGRAM backlog before ReceiveDatagram drains (silent drop when full).
// CONNECT-IP / MASQUE bulk can exceed transient drain headroom when queue is too small.
// Keep it configurable for constrained hosts while defaulting to a safer high-rate headroom.
var streamDatagramQueueLen = loadStreamDatagramQueueLen()

func loadStreamDatagramQueueLen() int {
	raw := os.Getenv("HIDDIFY_HTTP3_STREAM_DATAGRAM_QUEUE_LEN")
	if raw == "" {
		return defaultStreamDatagramQueueLen
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return defaultStreamDatagramQueueLen
	}
	if v < 128 {
		return 128
	}
	if v > 65536 {
		return 65536
	}
	return v
}

// stateTrackingStream is an implementation of quic.Stream that delegates
// to an underlying stream
// it takes care of proxying send and receive errors onto an implementation of
// the errorSetter interface (intended to be occupied by a datagrammer)
// it is also responsible for clearing the stream based on its ID from its
// parent connection, this is done through the streamClearer interface when
// both the send and receive sides are closed
type stateTrackingStream struct {
	*quic.Stream

	sendDatagram func([]byte) error
	hasData      chan struct{}
	// Fixed-capacity ring for inbound HTTP DATAGRAM frames (capacity = streamDatagramQueueLen).
	dgSlots [][]byte
	dgHead  int
	dgCount int

	mx      sync.Mutex
	sendErr error
	recvErr error

	clearer streamClearer
}

var _ datagramStream = &stateTrackingStream{}

type streamClearer interface {
	clearStream(quic.StreamID)
}

func newStateTrackingStream(s *quic.Stream, clearer streamClearer, sendDatagram func([]byte) error) *stateTrackingStream {
	capacity := streamDatagramQueueLen
	if capacity < 1 {
		capacity = 128
	}
	t := &stateTrackingStream{
		Stream:       s,
		clearer:      clearer,
		sendDatagram: sendDatagram,
		hasData:      make(chan struct{}, 1),
		dgSlots:      make([][]byte, capacity),
	}

	context.AfterFunc(s.Context(), func() {
		t.closeSend(context.Cause(s.Context()))
	})

	return t
}

func (s *stateTrackingStream) closeSend(e error) {
	s.mx.Lock()
	defer s.mx.Unlock()

	// clear the stream the first time both the send
	// and receive are finished
	if s.sendErr == nil {
		if s.recvErr != nil {
			s.clearer.clearStream(s.StreamID())
		}
		s.sendErr = e
	}
}

func (s *stateTrackingStream) closeReceive(e error) {
	s.mx.Lock()
	defer s.mx.Unlock()

	// clear the stream the first time both the send
	// and receive are finished
	if s.recvErr == nil {
		if s.sendErr != nil {
			s.clearer.clearStream(s.StreamID())
		}
		s.recvErr = e
		s.signalHasDatagram()
	}
}

func (s *stateTrackingStream) Close() error {
	s.closeSend(errors.New("write on closed stream"))
	return s.Stream.Close()
}

func (s *stateTrackingStream) CancelWrite(e quic.StreamErrorCode) {
	s.closeSend(&quic.StreamError{StreamID: s.StreamID(), ErrorCode: e})
	s.Stream.CancelWrite(e)
}

func (s *stateTrackingStream) Write(b []byte) (int, error) {
	n, err := s.Stream.Write(b)
	if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
		s.closeSend(err)
	}
	return n, err
}

func (s *stateTrackingStream) CancelRead(e quic.StreamErrorCode) {
	s.closeReceive(&quic.StreamError{StreamID: s.StreamID(), ErrorCode: e})
	s.Stream.CancelRead(e)
}

func (s *stateTrackingStream) Read(b []byte) (int, error) {
	n, err := s.Stream.Read(b)
	if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
		s.closeReceive(err)
	}
	return n, err
}

func (s *stateTrackingStream) SendDatagram(b []byte) error {
	s.mx.Lock()
	sendErr := s.sendErr
	s.mx.Unlock()
	if sendErr != nil {
		return sendErr
	}

	return s.sendDatagram(b)
}

func (s *stateTrackingStream) signalHasDatagram() {
	select {
	case s.hasData <- struct{}{}:
	default:
	}
}

func (s *stateTrackingStream) enqueueDatagram(data []byte) {
	s.mx.Lock()
	defer s.mx.Unlock()

	if s.recvErr != nil {
		streamDatagramRecvClosedDropTotal.Add(1)
		return
	}
	if s.dgCount >= streamDatagramQueueLen {
		streamDatagramQueueDropTotal.Add(1)
		return
	}
	idx := (s.dgHead + s.dgCount) % len(s.dgSlots)
	s.dgSlots[idx] = data
	s.dgCount++
	s.signalHasDatagram()
}

func (s *stateTrackingStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
start:
	s.mx.Lock()
	if s.dgCount > 0 {
		idx := s.dgHead
		data := s.dgSlots[idx]
		s.dgSlots[idx] = nil
		s.dgHead = (s.dgHead + 1) % len(s.dgSlots)
		s.dgCount--
		s.mx.Unlock()
		return data, nil
	}
	if receiveErr := s.recvErr; receiveErr != nil {
		s.mx.Unlock()
		return nil, receiveErr
	}
	s.mx.Unlock()

	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case <-s.hasData:
	}
	goto start
}

func (s *stateTrackingStream) QUICStream() *quic.Stream {
	return s.Stream
}
