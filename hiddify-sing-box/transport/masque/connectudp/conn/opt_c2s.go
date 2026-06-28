package conn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	h3WriteQueueCap       = 2048
	h3WriteHTTPBatchFlush = 32
	h3WriteCloseDrainWait = 2 * time.Second
	h3WriteQueueWait      = 700 * time.Millisecond
)

var h3WriteBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 2048)
		return &b
	},
}

type h3DatagramFlushSender interface {
	SendDatagramNoWake([]byte) error
	FlushProxiedIPDatagramSend()
}

// h3C2SWriter mirrors third_party/masque-go proxiedConn C2S: async writeCh + NoWake batch + buf pool.
type h3C2SWriter struct {
	str         interface{ SendDatagram([]byte) error }
	flushSender h3DatagramFlushSender
	writeCh     chan []byte
	writeDone   chan struct{}
	writeOnce      sync.Once
	writeCloseOnce sync.Once
	pumpBusy       sync.WaitGroup
	writeMu        sync.Mutex
	pendingBatch   int
	writeErr       atomic.Pointer[error]
}

func newH3C2SWriter(str interface{ SendDatagram([]byte) error }) *h3C2SWriter {
	w := &h3C2SWriter{str: str}
	if fs, ok := str.(h3DatagramFlushSender); ok {
		w.flushSender = fs
	}
	return w
}

func (w *h3C2SWriter) start() {
	if w.flushSender == nil {
		return
	}
	w.writeOnce.Do(func() {
		w.writeCh = make(chan []byte, h3WriteQueueCap)
		w.writeDone = make(chan struct{})
		go w.pump()
	})
}

func (w *h3C2SWriter) pump() {
	defer close(w.writeDone)
	for {
		data, ok := <-w.writeCh
		if !ok {
			break
		}
		w.pumpBusy.Add(1)
		batch := [][]byte{data}
		for len(w.writeCh) > 0 && len(batch) < h3WriteHTTPBatchFlush {
			batch = append(batch, <-w.writeCh)
		}
		for _, d := range batch {
			if err := w.sendDatagramUnlocked(d); err != nil {
				w.storeErr(err)
			}
			releaseH3WriteBuf(d)
		}
		w.flushPendingWriteBatch()
		w.pumpBusy.Done()
	}
	w.flushPendingWriteBatch()
}

func (w *h3C2SWriter) sendDatagramUnlocked(data []byte) error {
	if w.flushSender == nil {
		return w.str.SendDatagram(data)
	}
	if err := w.flushSender.SendDatagramNoWake(data); err != nil {
		return err
	}
	w.writeMu.Lock()
	w.pendingBatch++
	shouldFlush := w.pendingBatch >= h3WriteHTTPBatchFlush
	if shouldFlush {
		w.pendingBatch = 0
	}
	w.writeMu.Unlock()
	if shouldFlush {
		w.flushSender.FlushProxiedIPDatagramSend()
	}
	return nil
}

func (w *h3C2SWriter) flushPendingWriteBatch() {
	if w.flushSender == nil {
		return
	}
	if !w.writeMu.TryLock() {
		return
	}
	pending := w.pendingBatch
	w.pendingBatch = 0
	w.writeMu.Unlock()
	if pending > 0 {
		w.flushSender.FlushProxiedIPDatagramSend()
	}
}

func (w *h3C2SWriter) drainQueue() {
	w.awaitPumpIdle()
}

func (w *h3C2SWriter) awaitPumpIdle() {
	w.flushPendingWriteBatch()
	if w.writeCh == nil {
		return
	}
	deadline := time.Now().Add(h3WriteCloseDrainWait)
	for time.Now().Before(deadline) {
		if len(w.writeCh) == 0 {
			w.pumpBusy.Wait()
			w.flushPendingWriteBatch()
			if len(w.writeCh) == 0 {
				return
			}
		}
		time.Sleep(50 * time.Microsecond)
	}
}

func releaseH3WriteBuf(data []byte) {
	if cap(data) < 256 || cap(data) > h3WriteQueueCap*2 {
		return
	}
	b := data[:0]
	h3WriteBufPool.Put(&b)
}

func putH3WriteBuf(bufPtr *[]byte, data []byte) {
	*bufPtr = data[:0]
	h3WriteBufPool.Put(bufPtr)
}

func (w *h3C2SWriter) shutdown() {
	if w.writeCh != nil {
		w.writeCloseOnce.Do(func() {
			close(w.writeCh)
		})
		select {
		case <-w.writeDone:
		case <-time.After(h3WriteCloseDrainWait):
		}
	}
	w.flushPendingWriteBatch()
}

func (w *h3C2SWriter) writeBytes(ctx context.Context, closed *atomic.Bool, p []byte) error {
	if err := w.takeErr(); err != nil {
		return err
	}
	minCap := len(contextIDZero) + len(p)
	if w.flushSender != nil {
		w.start()
		bufPtr := h3WriteBufPool.Get().(*[]byte)
		data := *bufPtr
		if cap(data) < minCap {
			*bufPtr = data[:0]
			h3WriteBufPool.Put(bufPtr)
			data = make([]byte, minCap)
		} else {
			data = data[:minCap]
		}
		copy(data, contextIDZero)
		copy(data[len(contextIDZero):], p)
		w.writeMu.Lock()
		if closed != nil && closed.Load() {
			w.writeMu.Unlock()
			putH3WriteBuf(bufPtr, data)
			return net.ErrClosed
		}
		ch := w.writeCh
		w.writeMu.Unlock()
		if ch == nil {
			err := w.sendDatagramUnlocked(data)
			putH3WriteBuf(bufPtr, data)
			return err
		}
		select {
		case ch <- data:
			return nil
		case <-ctx.Done():
			putH3WriteBuf(bufPtr, data)
			if errors.Is(ctx.Err(), context.Canceled) {
				return ctx.Err()
			}
			return net.ErrClosed
		case <-time.After(h3WriteQueueWait):
			putH3WriteBuf(bufPtr, data)
			return fmt.Errorf("masque connect-udp: write queue blocked >%v", h3WriteQueueWait)
		}
	}
	bufPtr := h3WriteBufPool.Get().(*[]byte)
	data := *bufPtr
	if cap(data) >= minCap {
		data = data[:minCap]
		copy(data, contextIDZero)
		copy(data[len(contextIDZero):], p)
		err := w.sendDatagramUnlocked(data)
		*bufPtr = data[:0]
		h3WriteBufPool.Put(bufPtr)
		return err
	}
	*bufPtr = data[:0]
	h3WriteBufPool.Put(bufPtr)
	b := make([]byte, minCap)
	copy(b, contextIDZero)
	copy(b[len(contextIDZero):], p)
	return w.sendDatagramUnlocked(b)
}

func (w *h3C2SWriter) storeErr(err error) {
	if err != nil {
		e := err
		w.writeErr.Store(&e)
	}
}

func (w *h3C2SWriter) takeErr() error {
	if p := w.writeErr.Swap(nil); p != nil {
		return *p
	}
	return nil
}

var contextIDZero = []byte{0}
