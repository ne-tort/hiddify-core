package conn

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"time"
)

// ErrDeadlineUnsupported is returned when the underlying stream does not support deadlines.
var ErrDeadlineUnsupported = errors.New("conn: deadline not supported")

// h2DownloadBodyBufLen matches server relay bulk buffer (decoupled from stream/relay).
const h2DownloadBodyBufLen = 256 << 10

// h2ConnectStreamResponseBody wraps the HTTP/2 CONNECT response body for deadline-aware download I/O.
type h2ConnectStreamResponseBody struct {
	r  io.ReadCloser
	br *bufio.Reader
	dl connDeadlines
	mu sync.Mutex
	// inflightDrain is closed when a deadline-expired Read finishes draining the underlying read.
	inflightDrain chan struct{}
}

// NewH2ConnectStreamResponseBody wraps r with SetReadDeadline support for H2 CONNECT download.
func NewH2ConnectStreamResponseBody(r io.ReadCloser) io.ReadCloser {
	if r == nil {
		return nil
	}
	return &h2ConnectStreamResponseBody{r: r}
}

func (w *h2ConnectStreamResponseBody) SetReadDeadline(t time.Time) error {
	w.dl.setReadDeadline(t)
	return nil
}

func (w *h2ConnectStreamResponseBody) Read(p []byte) (int, error) {
	if w == nil || w.r == nil {
		return 0, io.EOF
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.waitInflightDrainLocked()
	if w.dl.readTimeoutExceeded() {
		return 0, os.ErrDeadlineExceeded
	}
	rNanos := w.dl.read.Load()
	if rNanos == 0 {
		return w.responseBodyReader().Read(p)
	}
	if time.Now().UnixNano() > rNanos {
		return 0, os.ErrDeadlineExceeded
	}
	rctx, rcancel := context.WithDeadline(context.Background(), time.Unix(0, rNanos))
	defer rcancel()
	r := w.r
	if r == nil {
		return 0, io.EOF
	}
	return w.awaitReadInterruptible(rctx, r, p)
}

func (w *h2ConnectStreamResponseBody) awaitReadInterruptible(ctx context.Context, r io.Reader, p []byte) (int, error) {
	if r == nil {
		return 0, io.EOF
	}
	ch := make(chan struct {
		n   int
		err error
	}, 1)
	go func() {
		n, err := r.Read(p)
		ch <- struct {
			n   int
			err error
		}{n, err}
	}()
	select {
	case <-ctx.Done():
		// Deadline poll / stopDownloadDrain poke must not Close the CONNECT response body —
		// WriteTo and later drain reads still own the same H2 download half (parity H3 poke).
		drainDone := make(chan struct{})
		w.inflightDrain = drainDone
		go func() {
			<-ch
			close(drainDone)
		}()
		if ce := context.Cause(ctx); errors.Is(ce, context.Canceled) {
			return 0, ce
		}
		return 0, os.ErrDeadlineExceeded
	case got := <-ch:
		return got.n, got.err
	}
}

func (w *h2ConnectStreamResponseBody) waitInflightDrainLocked() {
	ch := w.inflightDrain
	if ch == nil {
		return
	}
	w.mu.Unlock()
	<-ch
	w.mu.Lock()
	if w.inflightDrain == ch {
		w.inflightDrain = nil
	}
}

func (w *h2ConnectStreamResponseBody) responseBodyReader() io.Reader {
	if w.br == nil {
		w.br = bufio.NewReaderSize(w.r, h2DownloadBodyBufLen)
	}
	return w.br
}

func (w *h2ConnectStreamResponseBody) Close() error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	w.waitInflightDrainLocked()
	if w.r == nil {
		w.mu.Unlock()
		return nil
	}
	r := w.r
	w.r = nil
	w.br = nil
	w.inflightDrain = nil
	w.mu.Unlock()
	return r.Close()
}

