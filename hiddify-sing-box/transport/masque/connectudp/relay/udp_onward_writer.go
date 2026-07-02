package relay

import (
	"errors"
	"net"
	"sync"
)

const (
	OnwardUDPSendBatchMax    = 256
	onwardUDPPayloadBufCap   = 2048
)

var onwardUDPPayloadPool = sync.Pool{
	New: func() any {
		b := make([]byte, onwardUDPPayloadBufCap)
		return &b
	},
}

// OnwardUDPWriter batches kernel UDP sends for H2 asymmetric upload (masque-go WriteBatch shape).
type OnwardUDPWriter struct {
	batch    onwardUDPKernelBatch
	pending  [][]byte
	poolHold []*[]byte
}

// NewOnwardUDPWriter wraps a connected onward UDP socket for batched upload relay.
func NewOnwardUDPWriter(conn *net.UDPConn) *OnwardUDPWriter {
	w := &OnwardUDPWriter{
		batch:   newOnwardUDPKernelBatch(conn, OnwardUDPSendBatchMax),
		pending: make([][]byte, 0, OnwardUDPSendBatchMax),
	}
	return w
}

func (w *OnwardUDPWriter) recycleQueued() {
	for _, bp := range w.poolHold {
		onwardUDPPayloadPool.Put(bp)
	}
	w.poolHold = w.poolHold[:0]
}

func (w *OnwardUDPWriter) queueCopy(payload []byte) {
	bp := onwardUDPPayloadPool.Get().(*[]byte)
	buf := (*bp)[:len(payload):len(payload)]
	copy(buf, payload)
	w.pending = append(w.pending, buf)
	w.poolHold = append(w.poolHold, bp)
}

func (w *OnwardUDPWriter) writeOne(payload []byte) (icmp bool, err error) {
	return queueH2OnwardUDP(w.batch.writeConn, payload)
}

func (w *OnwardUDPWriter) writeFallback(payloads [][]byte) (icmp bool, err error) {
	for _, p := range payloads {
		icmp, err = w.writeOne(p)
		if icmp || err != nil {
			return icmp, err
		}
	}
	return false, nil
}

func (w *OnwardUDPWriter) writeBatch(payloads [][]byte) (icmp bool, err error) {
	if len(payloads) == 0 {
		return false, nil
	}
	if len(payloads) == 1 || !w.batch.enabled {
		return w.writeFallback(payloads)
	}
	werr := writeOnwardUDPPayloadBatch(&w.batch, payloads, nil)
	if werr == nil {
		return false, nil
	}
	if isOnwardICMPUnreachableWrite(werr) {
		return true, werr
	}
	return false, werr
}

// Queue copies one onward UDP payload; flushes when the batch is full.
func (w *OnwardUDPWriter) Queue(payload []byte) (icmp bool, err error) {
	if len(payload) == 0 {
		return false, nil
	}
	if len(payload) > onwardUDPPayloadBufCap {
		return false, errors.New("masque connect-udp onward: payload exceeds pool buffer")
	}
	w.queueCopy(payload)
	if len(w.pending) < OnwardUDPSendBatchMax {
		return false, nil
	}
	return w.Flush()
}

// Flush sends queued payloads.
func (w *OnwardUDPWriter) Flush() (icmp bool, err error) {
	if len(w.pending) == 0 {
		return false, nil
	}
	batch := w.pending
	w.pending = w.pending[:0]
	icmp, err = w.writeBatch(batch)
	w.recycleQueued()
	return icmp, err
}
