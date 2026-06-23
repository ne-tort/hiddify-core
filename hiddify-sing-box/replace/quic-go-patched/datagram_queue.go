package quic

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/utils/ringbuffer"
	"github.com/quic-go/quic-go/internal/wire"
)

const (
	// CONNECT-IP uses QUIC DATAGRAM for every IP frame; default 32/128 is sized for
	// occasional control traffic and drops under bursty tun/UDP load.
	maxDatagramSendQueueLen = 65536
	maxDatagramRcvQueueLen  = 262144
	// When upload DATA is pending, cap pure-ACK datagrams so download ACK floods do not
	// HOL-block C2S payload (TestLocalizeConnectIPUploadNativeConcurrentDownloadPollution).
	maxDatagramAckWhileData = 4096
	// NoWake enqueue must still schedule send when the queue is deep; otherwise Add blocks
	// without hasData and fountain S2C stalls (CONNECT-UDP bulk download).
	datagramNoWakeBlockWakeThreshold = 16
)

// datagramRcvQueueDropTotal counts inbound DATAGRAM frames dropped because rcvQueue
// reached maxDatagramRcvQueueLen (silent drop besides optional Debug log).
var datagramRcvQueueDropTotal atomic.Uint64

// DatagramReceiveQueueDropTotal returns receive-queue overflow drops (process-wide).
func DatagramReceiveQueueDropTotal() uint64 {
	return datagramRcvQueueDropTotal.Load()
}

type datagramQueue struct {
	sendMx sync.Mutex
	// sendData holds proxied-IP frames carrying TCP payload; sendAck holds pure ACK/control.
	sendData     ringbuffer.RingBuffer[*wire.DatagramFrame]
	sendAck      ringbuffer.RingBuffer[*wire.DatagramFrame]
	peekFromData bool
	sent         chan struct{} // used to notify Add that a datagram was dequeued

	rcvMx sync.Mutex
	// rcvRing is a fixed-capacity ring (len == maxDatagramRcvQueueLen when non-nil).
	// It replaces append/slice-reindex on rcvQueue which could retain a huge backing array
	// after bursts (CONNECT-IP / CONNECT-UDP high PPS) even when the logical queue drains.
	rcvRing  [][]byte
	rcvHead  int
	rcvCount int
	rcvd     chan struct{} // used to notify Receive that a new datagram was received

	closeErr error
	closed   chan struct{}

	hasData func()

	logger utils.Logger
}

func newDatagramQueue(hasData func(), logger utils.Logger) *datagramQueue {
	return &datagramQueue{
		hasData: hasData,
		rcvd:    make(chan struct{}, 1),
		sent:    make(chan struct{}, 1),
		closed:  make(chan struct{}),
		logger:  logger,
	}
}

func (h *datagramQueue) sendLenLocked() int {
	return h.sendData.Len() + h.sendAck.Len()
}

// SendLen returns queued outgoing DATAGRAM frames awaiting pack/send.
func (h *datagramQueue) SendLen() int {
	h.sendMx.Lock()
	defer h.sendMx.Unlock()
	return h.sendLenLocked()
}

func (h *datagramQueue) pushSendLocked(f *wire.DatagramFrame) {
	if masqueDatagramFrameHasTCPPayload(f) {
		h.sendData.PushBack(f)
		return
	}
	if !h.sendData.Empty() && h.sendAck.Len() >= maxDatagramAckWhileData {
		dropped := h.sendAck.PopFront()
		releaseOutgoingDatagramPayload(dropped)
	}
	h.sendAck.PushBack(f)
}

// Add queues a new DATAGRAM frame for sending and schedules the send loop.
// sendQueue grows up to maxDatagramSendQueueLen; beyond that Add blocks until a send drains the queue.
func (h *datagramQueue) Add(f *wire.DatagramFrame) error {
	return h.add(f, true)
}

// AddNoWake enqueues without scheduling send work — batched CONNECT-IP NoWake+Flush uses one wake per batch.
func (h *datagramQueue) AddNoWake(f *wire.DatagramFrame) error {
	return h.add(f, false)
}

func (h *datagramQueue) add(f *wire.DatagramFrame, wake bool) error {
	h.sendMx.Lock()

	for {
		// Closed must win over a spurious sentinel on h.sent once the send queue has
		// been drained synchronously inside CloseWithError (no Pop notification fired).
		select {
		case <-h.closed:
			err := h.closeErr
			h.sendMx.Unlock()
			return err
		default:
		}
		if h.sendLenLocked() < maxDatagramSendQueueLen {
			h.pushSendLocked(f)
			h.sendMx.Unlock()
			if wake {
				h.hasData()
			}
			return nil
		}
		// Queue full: re-poke send loop before blocking (CONNECT-UDP sustained upload stall).
		if h.sendLenLocked() >= datagramNoWakeBlockWakeThreshold {
			h.sendMx.Unlock()
			h.hasData()
			h.sendMx.Lock()
			continue
		}
		select {
		case <-h.sent: // drain the queue so we don't loop immediately
		default:
		}
		h.sendMx.Unlock()
		h.hasData()
		select {
		case <-h.closed:
			return h.closeErr
		case <-h.sent:
		}
		h.sendMx.Lock()
	}
}

// Peek gets the next DATAGRAM frame for sending.
// If actually sent out, Pop needs to be called before the next call to Peek.
func (h *datagramQueue) Peek() *wire.DatagramFrame {
	h.sendMx.Lock()
	defer h.sendMx.Unlock()
	return h.peekSendLocked()
}

func (h *datagramQueue) peekSendLocked() *wire.DatagramFrame {
	if !h.sendData.Empty() {
		h.peekFromData = true
		return h.sendData.PeekFront()
	}
	if !h.sendAck.Empty() {
		h.peekFromData = false
		return h.sendAck.PeekFront()
	}
	return nil
}

// Rotate moves the front DATAGRAM frame to the back of the active send queue.
// It returns false if the active queue has fewer than 2 elements.
func (h *datagramQueue) Rotate() bool {
	h.sendMx.Lock()
	defer h.sendMx.Unlock()
	q := &h.sendAck
	if !h.sendData.Empty() {
		q = &h.sendData
	}
	if q.Len() < 2 {
		return false
	}
	f := q.PopFront()
	q.PushBack(f)
	return true
}

func (h *datagramQueue) Pop() {
	h.sendMx.Lock()
	defer h.sendMx.Unlock()
	if h.peekFromData && !h.sendData.Empty() {
		_ = h.sendData.PopFront()
	} else if !h.sendAck.Empty() {
		_ = h.sendAck.PopFront()
	} else if !h.sendData.Empty() {
		_ = h.sendData.PopFront()
	}
	select {
	case h.sent <- struct{}{}:
	default:
	}
}

func (h *datagramQueue) ensureRcvRingLocked() [][]byte {
	if h.rcvRing == nil {
		h.rcvRing = make([][]byte, maxDatagramRcvQueueLen)
	}
	return h.rcvRing
}

// HandleDatagramFrame handles a received DATAGRAM frame.
func (h *datagramQueue) HandleDatagramFrame(f *wire.DatagramFrame) {
	data := acquireMasqueDatagramRecvBuf(len(f.Data))
	copy(data, f.Data)
	var queued bool
	h.rcvMx.Lock()
	ring := h.ensureRcvRingLocked()
	if h.rcvCount < maxDatagramRcvQueueLen {
		idx := (h.rcvHead + h.rcvCount) % len(ring)
		ring[idx] = data
		h.rcvCount++
		queued = true
		select {
		case h.rcvd <- struct{}{}:
		default:
		}
	} else {
		datagramRcvQueueDropTotal.Add(1)
	}
	h.rcvMx.Unlock()
	if !queued {
		if h.logger.Debug() {
			h.logger.Debugf("Discarding received DATAGRAM frame (%d bytes payload)", len(f.Data))
		}
	}
}

// TryReceive dequeues one received DATAGRAM payload without blocking when the recv
// queue already contains data (used to drain bursts on the HTTP/3 datagram goroutine).
func (h *datagramQueue) TryReceive() ([]byte, bool) {
	h.rcvMx.Lock()
	defer h.rcvMx.Unlock()
	if h.rcvCount == 0 {
		return nil, false
	}
	ring := h.ensureRcvRingLocked()
	idx := h.rcvHead
	data := ring[idx]
	ring[idx] = nil
	h.rcvHead = (h.rcvHead + 1) % len(ring)
	h.rcvCount--
	return data, true
}

// Receive gets a received DATAGRAM frame.
func (h *datagramQueue) Receive(ctx context.Context) ([]byte, error) {
	for {
		h.rcvMx.Lock()
		if h.rcvCount > 0 {
			ring := h.ensureRcvRingLocked()
			idx := h.rcvHead
			data := ring[idx]
			ring[idx] = nil
			h.rcvHead = (h.rcvHead + 1) % len(ring)
			h.rcvCount--
			h.rcvMx.Unlock()
			return data, nil
		}
		h.rcvMx.Unlock()
		select {
		case <-h.rcvd:
			continue
		case <-h.closed:
			return nil, h.closeErr
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (h *datagramQueue) drainSendLocked() {
	for !h.sendData.Empty() {
		f := h.sendData.PopFront()
		releaseOutgoingDatagramPayload(f)
	}
	for !h.sendAck.Empty() {
		f := h.sendAck.PopFront()
		releaseOutgoingDatagramPayload(f)
	}
}

func (h *datagramQueue) CloseWithError(e error) {
	h.closeErr = e
	close(h.closed)
	h.sendMx.Lock()
	h.drainSendLocked()
	h.sendMx.Unlock()
}
