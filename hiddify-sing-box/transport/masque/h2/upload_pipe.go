package h2

import (
	"io"
	"sync"
)

const connectUploadShallowPipeBuf = 128 << 10 // CONNECT-stream + CONNECT-UDP upload pipe

// uploadPipe is a bounded buffer between CONNECT upload producers and http2 writeRequestBody.
type uploadPipe struct {
	mu           sync.Mutex
	cond         sync.Cond
	buf          []byte
	cap          int
	writerClosed bool
	readerClosed bool
	writeErr     error
	flowWake     func()
}

func newUploadPipe(cap int) *uploadPipe {
	if cap <= 0 {
		cap = connectUploadShallowPipeBuf
	}
	p := &uploadPipe{cap: cap}
	p.cond.L = &p.mu
	return p
}

// ConnectUploadPipeWriter is the client upload half of a CONNECT upload pipe.
type ConnectUploadPipeWriter interface {
	io.WriteCloser
	MasqueUploadWriterOpen() bool
}

// ExportConnectUploadShallowPipeBuf exposes CONNECT-stream upload pipe size for gates.
func ExportConnectUploadShallowPipeBuf() int { return connectUploadShallowPipeBuf }

// NewConnectUploadPipe returns reader/writer for Extended CONNECT upload (128 KiB).
func NewConnectUploadPipe() (io.ReadCloser, ConnectUploadPipeWriter) {
	p := newUploadPipe(connectUploadShallowPipeBuf)
	return &uploadPipeReader{p: p}, &uploadPipeWriter{p: p}
}

// NewConnectUploadShallowPipe returns a bounded upload buffer for CONNECT-UDP.
func NewConnectUploadShallowPipe() (io.ReadCloser, ConnectUploadPipeWriter) {
	p := newUploadPipe(connectUploadShallowPipeBuf)
	return &uploadPipeReader{p: p}, &uploadPipeWriter{p: p}
}

type uploadPipeReader struct{ p *uploadPipe }

func (r *uploadPipeReader) MasqueUploadBuffered() int {
	up := r.p
	up.mu.Lock()
	defer up.mu.Unlock()
	return len(up.buf)
}

func (r *uploadPipeReader) UploadPipeCap() int {
	if r == nil || r.p == nil {
		return 0
	}
	return r.p.cap
}

func (r *uploadPipeReader) MasqueUploadWriterOpen() bool {
	if r == nil || r.p == nil {
		return false
	}
	up := r.p
	up.mu.Lock()
	defer up.mu.Unlock()
	return !up.writerClosed
}

func (r *uploadPipeReader) SetMasqueUploadFlowWake(fn func()) {
	if r == nil || r.p == nil {
		return
	}
	up := r.p
	up.mu.Lock()
	up.flowWake = fn
	up.mu.Unlock()
}

func (r *uploadPipeReader) MasqueWakeUploadFlow() {
	if r == nil || r.p == nil {
		return
	}
	up := r.p
	up.mu.Lock()
	wake := up.flowWake
	up.mu.Unlock()
	if wake != nil {
		wake()
	}
}

func (r *uploadPipeReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	up := r.p
	up.mu.Lock()
	defer up.mu.Unlock()
	for {
		if len(up.buf) > 0 {
			n := copy(p, up.buf)
			up.buf = up.buf[n:]
			up.cond.Signal()
			return n, nil
		}
		if up.readerClosed {
			return 0, io.ErrClosedPipe
		}
		if up.writerClosed {
			if up.writeErr != nil {
				return 0, up.writeErr
			}
			return 0, io.EOF
		}
		up.cond.Wait()
	}
}

func (r *uploadPipeReader) Close() error {
	up := r.p
	up.mu.Lock()
	defer up.mu.Unlock()
	up.readerClosed = true
	up.cond.Broadcast()
	return nil
}

type uploadPipeWriter struct{ p *uploadPipe }

func (w *uploadPipeWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	up := w.p
	up.mu.Lock()
	total := 0
	var wake func()
	defer func() {
		up.mu.Unlock()
		if wake != nil {
			wake()
		}
	}()
	if up.writerClosed {
		return 0, io.ErrClosedPipe
	}
	for len(p) > 0 {
		for len(up.buf) >= up.cap && !up.writerClosed {
			up.cond.Wait()
			if up.writerClosed {
				return total, io.ErrClosedPipe
			}
		}
		if up.writerClosed {
			return total, io.ErrClosedPipe
		}
		space := up.cap - len(up.buf)
		if space == 0 {
			continue
		}
		n := len(p)
		if n > space {
			n = space
		}
		up.buf = append(up.buf, p[:n]...)
		p = p[n:]
		total += n
		up.cond.Signal()
		wake = up.flowWake
	}
	return total, nil
}

func (w *uploadPipeWriter) Close() error {
	up := w.p
	up.mu.Lock()
	defer up.mu.Unlock()
	if up.writerClosed {
		return nil
	}
	up.writerClosed = true
	up.cond.Broadcast()
	return nil
}

func (w *uploadPipeWriter) PokeH2BidiDownload() {
	if w == nil || w.p == nil {
		return
	}
	up := w.p
	up.mu.Lock()
	wake := up.flowWake
	up.mu.Unlock()
	if wake != nil {
		wake()
	}
}

func (w *uploadPipeWriter) MasqueUploadWriterOpen() bool {
	if w == nil || w.p == nil {
		return false
	}
	up := w.p
	up.mu.Lock()
	defer up.mu.Unlock()
	return !up.writerClosed
}
