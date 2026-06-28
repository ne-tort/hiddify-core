package h2

import (
	"io"
	"sync"
)

const connectUploadPipeBuf = 8 << 20

// uploadPipe is a bounded buffer between CONNECT upload producers and http2 writeRequestBody.
// io.Pipe blocks on every chunk; this decouples C2S coalesce from TLS flush cadence.
type uploadPipe struct {
	mu       sync.Mutex
	cond     sync.Cond
	buf      []byte
	cap      int
	closed   bool
	writeErr error
}

func newUploadPipe(cap int) *uploadPipe {
	if cap <= 0 {
		cap = connectUploadPipeBuf
	}
	p := &uploadPipe{cap: cap}
	p.cond.L = &p.mu
	return p
}

// NewConnectUploadPipe returns reader/writer for Extended CONNECT upload (replaces io.Pipe).
func NewConnectUploadPipe() (io.ReadCloser, io.WriteCloser) {
	p := newUploadPipe(connectUploadPipeBuf)
	return &uploadPipeReader{p: p}, &uploadPipeWriter{p: p}
}

type uploadPipeReader struct{ p *uploadPipe }

// MasqueUploadBuffered reports bytes waiting in the upload pipe (0 = next Read may block).
func (r *uploadPipeReader) MasqueUploadBuffered() int {
	up := r.p
	up.mu.Lock()
	defer up.mu.Unlock()
	return len(up.buf)
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
		if up.closed {
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
	up.closed = true
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
	defer up.mu.Unlock()
	if up.closed {
		return 0, io.ErrClosedPipe
	}
	total := 0
	for len(p) > 0 {
		for len(up.buf) >= up.cap && !up.closed {
			up.cond.Wait()
			if up.closed {
				return total, io.ErrClosedPipe
			}
		}
		if up.closed {
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
	}
	return total, nil
}

func (w *uploadPipeWriter) Close() error {
	up := w.p
	up.mu.Lock()
	defer up.mu.Unlock()
	if up.closed {
		return nil
	}
	up.closed = true
	up.cond.Broadcast()
	return nil
}
