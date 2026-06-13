package stream

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
var ErrDeadlineUnsupported = errors.New("stream: deadline not supported")

// h2ConnectStreamResponseBody wraps the HTTP/2 CONNECT response body for deadline-aware download I/O.
type h2ConnectStreamResponseBody struct {
	r  io.ReadCloser
	br *bufio.Reader
	dl connDeadlines
	mu sync.Mutex
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
	return w.awaitReadInterruptible(rctx, p)
}

func (w *h2ConnectStreamResponseBody) awaitReadInterruptible(ctx context.Context, p []byte) (int, error) {
	ch := make(chan struct {
		n   int
		err error
	}, 1)
	go func() {
		n, err := w.r.Read(p)
		ch <- struct {
			n   int
			err error
		}{n, err}
	}()
	select {
	case <-ctx.Done():
		_ = w.r.Close()
		got := <-ch
		_ = got
		if ce := context.Cause(ctx); errors.Is(ce, context.Canceled) {
			return 0, ce
		}
		return 0, os.ErrDeadlineExceeded
	case got := <-ch:
		return got.n, got.err
	}
}

func (w *h2ConnectStreamResponseBody) responseBodyReader() io.Reader {
	if w.br == nil {
		w.br = bufio.NewReaderSize(w.r, RelayTunnelBufLen)
	}
	return w.br
}

func (w *h2ConnectStreamResponseBody) Close() error {
	if w.r == nil {
		return nil
	}
	return w.r.Close()
}

