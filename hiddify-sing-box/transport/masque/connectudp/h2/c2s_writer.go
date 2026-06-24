package h2

import (
	"io"
	"sync"
	"sync/atomic"
	"time"

	h2c "github.com/sagernet/sing-box/transport/masque/h2"
)

const (
	h2C2SWriteQueueCap       = 2048
	h2C2SWriteCloseDrainWait = 2 * time.Second
)

type c2sWriteJob struct {
	wire []byte
	done chan error
}

// c2sWriter async-uploads CONNECT-UDP wire to the HTTP/2 request body (SOCKS relay parity H3 h3C2SWriter).
// enqueue blocks until the batch is written to the upload pipe (2 MiB buffer decouples TLS flush).
type c2sWriter struct {
	reqBody        io.WriteCloser
	writeCh        chan c2sWriteJob
	writeDone      chan struct{}
	writeOnce      sync.Once
	writeCloseOnce sync.Once
	writeErr       atomic.Pointer[error]
}

func newC2SWriter(reqBody io.WriteCloser) *c2sWriter {
	if reqBody == nil {
		return nil
	}
	return &c2sWriter{reqBody: reqBody}
}

func (w *c2sWriter) start() {
	if w == nil || w.reqBody == nil {
		return
	}
	w.writeOnce.Do(func() {
		w.writeCh = make(chan c2sWriteJob, h2C2SWriteQueueCap)
		w.writeDone = make(chan struct{})
		go w.pump()
	})
}

func (w *c2sWriter) pump() {
	defer close(w.writeDone)
	mergeScratch := make([]byte, 0, 256*1024)
	pending := make([]c2sWriteJob, 0, 8)
	for job := range w.writeCh {
		pending = append(pending[:0], job)
		for len(w.writeCh) > 0 {
			pending = append(pending, <-w.writeCh)
		}
		mergeScratch = mergeScratch[:0]
		for i := range pending {
			mergeScratch = append(mergeScratch, pending[i].wire...)
		}
		err := w.writeWire(mergeScratch)
		if err == nil {
			h2c.FlushRequestBody(w.reqBody)
		}
		if err != nil {
			w.storeErr(err)
		}
		for i := range pending {
			pending[i].done <- err
		}
	}
	h2c.FlushRequestBody(w.reqBody)
}

func (w *c2sWriter) writeWire(wire []byte) error {
	if len(wire) == 0 {
		return nil
	}
	_, err := h2c.WriteAll(w.reqBody, wire)
	return err
}

func (w *c2sWriter) enqueue(wire []byte) error {
	if w == nil {
		return nil
	}
	if err := w.takeErr(); err != nil {
		return err
	}
	if len(wire) == 0 {
		return nil
	}
	job := c2sWriteJob{
		wire: append([]byte(nil), wire...),
		done: make(chan error, 1),
	}
	w.start()
	w.writeCh <- job
	return <-job.done
}

func (w *c2sWriter) drainQueue() {
	if w == nil {
		return
	}
	if w.writeCh == nil {
		return
	}
	deadline := time.Now().Add(h2C2SWriteCloseDrainWait)
	for time.Now().Before(deadline) {
		if len(w.writeCh) == 0 {
			return
		}
		time.Sleep(50 * time.Microsecond)
	}
}

func (w *c2sWriter) close() {
	if w == nil || w.writeCh == nil {
		return
	}
	w.writeCloseOnce.Do(func() {
		close(w.writeCh)
	})
	select {
	case <-w.writeDone:
	case <-time.After(h2C2SWriteCloseDrainWait):
	}
}

func (w *c2sWriter) storeErr(err error) {
	if err != nil {
		w.writeErr.Store(&err)
	}
}

func (w *c2sWriter) takeErr() error {
	if p := w.writeErr.Swap(nil); p != nil {
		return *p
	}
	return nil
}
