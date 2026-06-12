package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	tcpDownloadFlushEvery     = TCPDownloadFlushEvery
	tcpDownloadReadLen        = TCPDownloadReadLen
	tcpUploadReadLen          = TCPUploadReadLen
	tcpResponseFlushEvery     = TCPResponseFlushEvery
	tcpResponseFlushImmediate = TCPResponseFlushImmediate
	tcpCopyBufLen             = TCPCopyBufLen
)

var (
	tcpUploadBufPool = sync.Pool{
		New: func() any {
			b := make([]byte, tcpUploadReadLen)
			return &b
		},
	}
	tcpDownloadBufPool = sync.Pool{
		New: func() any {
			b := make([]byte, tcpDownloadReadLen)
			return &b
		},
	}
	tcpCopyBufPool = sync.Pool{
		New: func() any {
			b := make([]byte, tcpCopyBufLen)
			return &b
		},
	}
)

func relayCopyBuffered(dst io.Writer, src io.Reader) (int64, error) {
	bp := tcpCopyBufPool.Get().(*[]byte)
	defer tcpCopyBufPool.Put(bp)
	return io.CopyBuffer(dst, src, *bp)
}

// downloadCopy relays onward TCP → HTTP response with batched flushes (not every 64 KiB read).
func downloadCopy(out *flushWriter, src io.Reader) (int64, error) {
	bp := tcpDownloadBufPool.Get().(*[]byte)
	defer tcpDownloadBufPool.Put(bp)
	buf := *bp
	var written int64
	var sinceFlush int
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := out.writeRaw(buf[:nr])
			written += int64(nw)
			if ew != nil {
				return written, ew
			}
			if nw < nr {
				return written, io.ErrShortWrite
			}
			sinceFlush += nw
			out.firstFlushDone = true
			if err := out.flushWithReason("relay_read"); err != nil {
				return written, err
			}
			sinceFlush = 0
		}
		if er != nil {
			if errors.Is(er, io.EOF) {
				return written, nil
			}
			return written, er
		}
		if nr == 0 {
			return written, nil
		}
	}
}

// uploadCopy drains the CONNECT-stream request body to onward TCP in download-sized chunks.
func uploadCopy(dst io.Writer, src io.ReadCloser) (int64, error) {
	defer src.Close()
	bp := tcpUploadBufPool.Get().(*[]byte)
	defer tcpUploadBufPool.Put(bp)
	buf := *bp
	var written int64
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			written += int64(nw)
			if ew != nil {
				return written, ew
			}
			if nw < nr {
				return written, io.ErrShortWrite
			}
		}
		if er != nil {
			if errors.Is(er, io.EOF) {
				return written, nil
			}
			return written, er
		}
		if nr == 0 {
			return written, nil
		}
	}
}

// primeTCPDownloadChunk reads the first onward-TCP segment when the target sends before the client.
func primeTCPDownloadChunk(conn net.Conn) ([]byte, error) {
	buf := make([]byte, 4096)
	if d, ok := conn.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = d.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		defer func() { _ = d.SetReadDeadline(time.Time{}) }()
	}
	n, err := conn.Read(buf)
	if n > 0 {
		return buf[:n], nil
	}
	if err == nil {
		return nil, nil
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return nil, nil
	}
	if errors.Is(err, io.EOF) {
		return nil, err
	}
	return nil, err
}

// TCPBidirectional is the legacy per-read flush relay (MASQUE_RELAY_TCP_LEGACY=1).
func TCPBidirectional(ctx context.Context, targetConn net.Conn, reqBody io.ReadCloser, responseWriter io.Writer) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var flusher http.Flusher
	if f, ok := responseWriter.(http.Flusher); ok {
		flusher = f
	}
	out := newFlushWriter(responseWriter, flusher)
	uploadErrCh := make(chan error, 1)
	downloadErrCh := make(chan error, 1)
	go func() {
		_, err := uploadCopy(targetConn, reqBody)
		if cw, ok := targetConn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		uploadErrCh <- err
	}()
	go func() {
		if prime, err := primeTCPDownloadChunk(targetConn); err != nil {
			downloadErrCh <- err
			return
		} else if len(prime) > 0 {
			if _, err := out.Write(prime); err != nil {
				downloadErrCh <- err
				return
			}
			if err := out.flushWithReason("prime"); err != nil {
				downloadErrCh <- err
				return
			}
		}
		_, err := downloadCopy(out, targetConn)
		if flushErr := out.flushWithReason("relay_done"); err == nil {
			err = flushErr
		}
		downloadErrCh <- err
	}()
	select {
	case <-ctx.Done():
		_ = targetConn.Close()
		_ = reqBody.Close()
		uploadErr := <-uploadErrCh
		downloadErr := <-downloadErrCh
		return errors.Join(context.Cause(ctx), uploadErr, downloadErr)
	case uploadErr := <-uploadErrCh:
		if uploadErr != nil && !errors.Is(uploadErr, io.EOF) {
			_ = targetConn.Close()
		}
		downloadErr := <-downloadErrCh
		_ = targetConn.Close()
		_ = reqBody.Close()
		return errors.Join(uploadErr, downloadErr)
	}
}

type flushWriter struct {
	w              io.Writer
	f              http.Flusher
	pendingFlush   int
	firstFlushDone bool
}

func newFlushWriter(w io.Writer, f http.Flusher) *flushWriter {
	return &flushWriter{w: w, f: f}
}

func (w *flushWriter) flush() {
	_ = w.flushWithReason("explicit")
}

func (w *flushWriter) flushWithReason(reason string) error {
	if w == nil || w.w == nil {
		return nil
	}
	traceFlush(reason, w.pendingFlush, w.firstFlushDone)
	var rcErr error
	if rw, ok := w.w.(http.ResponseWriter); ok {
		rcErr = http.NewResponseController(rw).Flush()
	}
	if w.f != nil {
		w.f.Flush()
	}
	w.pendingFlush = 0
	if w.f == nil && rcErr != nil && !errors.Is(rcErr, http.ErrNotSupported) {
		return rcErr
	}
	return nil
}

func (w *flushWriter) writeRaw(p []byte) (int, error) {
	nn := 0
	for nn < len(p) {
		n, err := w.w.Write(p[nn:])
		nn += n
		if err != nil {
			return nn, err
		}
		if n == 0 {
			return nn, io.ErrShortWrite
		}
	}
	return nn, nil
}

func (w *flushWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	nn, err := w.writeRaw(p)
	if err != nil {
		return nn, err
	}
	if nn > 0 {
		w.pendingFlush += nn
		traceFlushWrite(nn, w.pendingFlush, w.firstFlushDone)
		switch {
		case !w.firstFlushDone && w.pendingFlush > 0:
			if err := w.flushWithReason("first_flight"); err != nil {
				return nn, err
			}
			w.firstFlushDone = true
		case w.pendingFlush >= tcpResponseFlushEvery:
			if err := w.flushWithReason("threshold"); err != nil {
				return nn, err
			}
		case w.pendingFlush >= tcpDownloadFlushEvery:
			if err := w.flushWithReason("relay_chunk"); err != nil {
				return nn, err
			}
		case w.pendingFlush <= tcpResponseFlushImmediate:
			if err := w.flushWithReason("immediate"); err != nil {
				return nn, err
			}
		}
	}
	return nn, nil
}

func traceFlushWrite(n int, pending int, firstDone bool) {
	if strings.TrimSpace(os.Getenv("MASQUE_TRACE_RELAY_FLUSH")) != "1" {
		return
	}
	fmt.Fprintf(os.Stderr, "MASQUE_RELAY_FLUSH event=write n=%d pending=%d first_done=%t\n", n, pending, firstDone)
}

func traceFlush(reason string, pending int, firstDone bool) {
	if strings.TrimSpace(os.Getenv("MASQUE_TRACE_RELAY_FLUSH")) != "1" {
		return
	}
	fmt.Fprintf(os.Stderr, "MASQUE_RELAY_FLUSH event=flush reason=%s pending=%d first_done=%t\n", reason, pending, firstDone)
}
