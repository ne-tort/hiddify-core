package http3

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"

	"github.com/quic-go/quic-go"
)

const streamDatagramQueueLen = 65536

var (
	streamDatagramQueueDropTotal      atomic.Uint64
	streamDatagramRecvClosedDropTotal atomic.Uint64
)

func StreamDatagramQueueDropTotal() uint64 {
	return streamDatagramQueueDropTotal.Load()
}

func StreamDatagramRecvClosedDropTotal() uint64 {
	return streamDatagramRecvClosedDropTotal.Load()
}

type stateTrackingStream struct {
	*quic.Stream

	sendDatagram       func([]byte) error
	sendDatagramNoWake func([]byte) error
	hasData            chan struct{}
	queue              [][]byte
	queueHead          int
	queueCount         int

	sendMx  sync.Mutex
	recvMx  sync.Mutex
	sendErr error
	recvErr error

	clearer streamClearer
}

var _ datagramStream = &stateTrackingStream{}

type streamClearer interface {
	clearStream(quic.StreamID)
}

func newStateTrackingStream(s *quic.Stream, clearer streamClearer, sendDatagram, sendDatagramNoWake func([]byte) error) *stateTrackingStream {
	t := &stateTrackingStream{
		Stream:             s,
		clearer:            clearer,
		sendDatagram:       sendDatagram,
		sendDatagramNoWake: sendDatagramNoWake,
		hasData:            make(chan struct{}, 1),
	}
	context.AfterFunc(s.Context(), func() {
		t.closeSend(context.Cause(s.Context()))
	})
	return t
}

func (s *stateTrackingStream) maybeClearStream() {
	s.sendMx.Lock()
	s.recvMx.Lock()
	if s.sendErr != nil && s.recvErr != nil {
		s.clearer.clearStream(s.StreamID())
	}
	s.recvMx.Unlock()
	s.sendMx.Unlock()
}

func (s *stateTrackingStream) closeSend(e error) {
	s.sendMx.Lock()
	if s.sendErr == nil {
		s.sendErr = e
	}
	s.sendMx.Unlock()
	s.maybeClearStream()
}

func (s *stateTrackingStream) closeReceive(e error) {
	s.recvMx.Lock()
	if s.recvErr == nil {
		s.recvErr = e
		s.signalHasDatagram()
	}
	s.recvMx.Unlock()
	s.maybeClearStream()
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
	s.sendMx.Lock()
	sendErr := s.sendErr
	s.sendMx.Unlock()
	if sendErr != nil {
		return sendErr
	}
	return s.sendDatagram(b)
}

func (s *stateTrackingStream) SendDatagramNoWake(b []byte) error {
	s.sendMx.Lock()
	sendErr := s.sendErr
	s.sendMx.Unlock()
	if sendErr != nil {
		return sendErr
	}
	if s.sendDatagramNoWake == nil {
		return s.sendDatagram(b)
	}
	return s.sendDatagramNoWake(b)
}

func (s *stateTrackingStream) signalHasDatagram() {
	select {
	case s.hasData <- struct{}{}:
	default:
	}
}

func (s *stateTrackingStream) popQueueLocked() ([]byte, bool) {
	if s.queueCount == 0 || s.queue == nil {
		return nil, false
	}
	data := s.queue[s.queueHead]
	s.queue[s.queueHead] = nil
	s.queueHead = (s.queueHead + 1) % streamDatagramQueueLen
	s.queueCount--
	return data, true
}

func (s *stateTrackingStream) enqueueDatagram(data []byte) {
	owned := quic.AcquireMasqueDatagramRecvBuf(len(data))
	copy(owned, data)
	if !s.enqueueDatagramOwned(owned) {
		quic.ReleaseMasqueDatagramReceiveBuffer(owned)
	}
}

// enqueueDatagramOwned queues a pooled receive buffer without copying (caller transfers ownership).
func (s *stateTrackingStream) enqueueDatagramOwned(owned []byte) bool {
	s.recvMx.Lock()
	defer s.recvMx.Unlock()
	if s.recvErr != nil {
		streamDatagramRecvClosedDropTotal.Add(1)
		return false
	}
	if s.queueCount >= streamDatagramQueueLen {
		streamDatagramQueueDropTotal.Add(1)
		return false
	}
	if s.queue == nil {
		s.queue = make([][]byte, streamDatagramQueueLen)
	}
	tail := (s.queueHead + s.queueCount) % streamDatagramQueueLen
	s.queue[tail] = owned
	s.queueCount++
	s.signalHasDatagram()
	return true
}

func (s *stateTrackingStream) TryReceiveDatagram() ([]byte, bool) {
	s.recvMx.Lock()
	defer s.recvMx.Unlock()
	return s.popQueueLocked()
}

func (s *stateTrackingStream) ReceiveDatagram(ctx context.Context) ([]byte, error) {
start:
	s.recvMx.Lock()
	if data, ok := s.popQueueLocked(); ok {
		s.recvMx.Unlock()
		return data, nil
	}
	if receiveErr := s.recvErr; receiveErr != nil {
		s.recvMx.Unlock()
		return nil, receiveErr
	}
	s.recvMx.Unlock()
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
