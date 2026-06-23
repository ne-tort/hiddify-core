package conn

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

const (
	h3WriteQueueCap       = 2048
	h3WriteHTTPBatchFlush = 8
	h3WriteCloseDrainWait = 2 * time.Second
)

type h3DatagramFlushSender interface {
	SendDatagramNoWake([]byte) error
	FlushProxiedIPDatagramSend()
}

// h3C2SWriter async writeCh + NoWake batch N=8 + idle tail flush (kept stack 3cl+3ct).
type h3C2SWriter struct {
	str          interface{ SendDatagram([]byte) error }
	flushSender  h3DatagramFlushSender
	writeCh      chan []byte
	writeDone    chan struct{}
	writeOnce      sync.Once
	writeCloseOnce sync.Once
	writeMu        sync.Mutex
	pendingBatch int
	writeErr     atomic.Pointer[error]
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
		w.writeMu.Lock()
		if err := w.sendLocked(data); err != nil {
			w.storeErr(err)
		}
		for len(w.writeCh) > 0 {
			data = <-w.writeCh
			if err := w.sendLocked(data); err != nil {
				w.storeErr(err)
			}
		}
		w.flushLocked()
		w.writeMu.Unlock()
	}
	w.writeMu.Lock()
	w.flushLocked()
	w.writeMu.Unlock()
}

func (w *h3C2SWriter) sendLocked(data []byte) error {
	if w.flushSender == nil {
		return w.str.SendDatagram(data)
	}
	if err := w.flushSender.SendDatagramNoWake(data); err != nil {
		return err
	}
	w.pendingBatch++
	if w.pendingBatch >= h3WriteHTTPBatchFlush {
		w.pendingBatch = 0
		w.flushSender.FlushProxiedIPDatagramSend()
	}
	return nil
}

func (w *h3C2SWriter) flushLocked() {
	if w.flushSender == nil || w.pendingBatch == 0 {
		return
	}
	w.pendingBatch = 0
	w.flushSender.FlushProxiedIPDatagramSend()
}

func (w *h3C2SWriter) flushPending() {
	if w.flushSender == nil {
		return
	}
	w.writeMu.Lock()
	w.flushLocked()
	w.writeMu.Unlock()
}

func (w *h3C2SWriter) drainQueue() {
	w.flushPending()
	if w.writeCh == nil {
		return
	}
	deadline := time.Now().Add(h3WriteCloseDrainWait)
	for time.Now().Before(deadline) {
		if len(w.writeCh) == 0 {
			return
		}
		time.Sleep(50 * time.Microsecond)
	}
}

func (w *h3C2SWriter) enqueue(ctx context.Context, p []byte) error {
	if err := w.takeErr(); err != nil {
		return err
	}
	data := make([]byte, len(contextIDZero)+len(p))
	copy(data, contextIDZero)
	copy(data[len(contextIDZero):], p)
	if w.flushSender == nil {
		return w.str.SendDatagram(data)
	}
	w.start()
	select {
	case w.writeCh <- data:
		return nil
	case <-ctx.Done():
		return net.ErrClosed
	}
}

func (w *h3C2SWriter) close(ctx context.Context) {
	w.flushPending()
	if w.writeCh == nil {
		return
	}
	w.writeCloseOnce.Do(func() {
		close(w.writeCh)
	})
	select {
	case <-w.writeDone:
	case <-ctx.Done():
	case <-time.After(h3WriteCloseDrainWait):
	}
}

func (w *h3C2SWriter) storeErr(err error) {
	if err != nil {
		w.writeErr.Store(&err)
	}
}

func (w *h3C2SWriter) takeErr() error {
	if p := w.writeErr.Swap(nil); p != nil {
		return *p
	}
	return nil
}

// skipCapsules drains ignored capsules on the CONNECT-UDP request stream with bounded reads.
func skipCapsules(str quicvarint.Reader) error {
	const (
		skipCapsuleDatagramMaxPayload    = 1500 + 128
		skipCapsuleNondatagramMaxPayload = 65536
		capsuleTypeDatagram              = http3.CapsuleType(0)
	)
	for {
		ct, r, err := http3.ParseCapsule(str)
		if err != nil {
			return err
		}
		max := int64(skipCapsuleNondatagramMaxPayload)
		if ct == capsuleTypeDatagram {
			max = int64(skipCapsuleDatagramMaxPayload)
		}
		n, err := io.Copy(io.Discard, io.LimitReader(r, max+1))
		if err != nil {
			return err
		}
		if n > max {
			return fmt.Errorf("masque connect-udp h3 skip-capsules: type=%d capsule exceeds %d bytes", ct, max)
		}
	}
}

var contextIDZero = []byte{0}
