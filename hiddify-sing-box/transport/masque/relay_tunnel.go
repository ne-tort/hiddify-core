package masque

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

	"github.com/quic-go/quic-go/http3"
)

// RelayTunnelBufLen matches h2o proxy.max-buffer-size (65536) on MASQUE CONNECT tunnels.
const RelayTunnelBufLen = 64 * 1024

var relayTunnelBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, RelayTunnelBufLen)
		return &b
	},
}

// RelayUseHTTP3StreamHijack enables hijacked *http3.Stream relay (default on).
// Set MASQUE_RELAY_TCP_STREAM_HIJACK=0 to disable.
func RelayUseHTTP3StreamHijack() bool {
	return strings.TrimSpace(os.Getenv("MASQUE_RELAY_TCP_STREAM_HIJACK")) != "0"
}

// RelayUploadFromStream reads client upload from the hijacked HTTP/3 stream instead of req.Body.
// Env: MASQUE_THIN_RELAY_UPLOAD (str/stream default) or MASQUE_RELAY_TCP_UPLOAD_BODY=1 for req.Body.
func RelayUploadFromStream() bool {
	if body := strings.TrimSpace(os.Getenv("MASQUE_RELAY_TCP_UPLOAD_BODY")); body != "" {
		switch body {
		case "1", "reqbody", "body", "true", "yes":
			return false
		default:
			return true
		}
	}
	switch strings.TrimSpace(os.Getenv("MASQUE_THIN_RELAY_UPLOAD")) {
	case "str", "stream":
		return true
	case "reqbody", "body", "0":
		return false
	default:
		if thin := strings.TrimSpace(os.Getenv("MASQUE_THIN_RELAY_UPLOAD")); thin != "" {
			return thin != "0" && thin != "reqbody"
		}
		return true
	}
}

// RelayTCPTunnel relays CONNECT tunneled TCP like h2o proxy.tunnel (64 KiB io.CopyBuffer, full duplex).
func RelayTCPTunnel(ctx context.Context, targetConn net.Conn, reqBody io.ReadCloser, responseWriter http.ResponseWriter) error {
	if RelayUseHTTP3StreamHijack() {
		if str := h3StreamFromCONNECTRelay(reqBody, responseWriter); str != nil {
			return relayTCPTunnelH3Stream(ctx, targetConn, reqBody, str)
		}
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	_ = http.NewResponseController(responseWriter).EnableFullDuplex()
	type closeWriter interface {
		CloseWrite() error
	}
	uploadErrCh := make(chan error, 1)
	downloadErrCh := make(chan error, 1)
	go func() {
		_, err := relayTunnelCopyBuffer(targetConn, reqBody)
		_ = reqBody.Close()
		if cw, ok := targetConn.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
		uploadErrCh <- err
	}()
	go func() {
		out := relayTunnelDownloadWriter(responseWriter)
		_, err := relayTunnelDownloadRelay(out, responseWriter, targetConn)
		downloadErrCh <- err
	}()
	return relayTunnelSelect(ctx, targetConn, reqBody, uploadErrCh, downloadErrCh)
}

// relayTunnelPrimeDownload reads the first onward-TCP segment (iperf banner, etc.). Timeout with no bytes is OK.
func relayTunnelPrimeDownload(conn net.Conn) ([]byte, error) {
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

// relayTunnelDownloadRelay copies onward TCP → CONNECT response with a flush per read (H2 iperf -R).
func relayTunnelDownloadRelay(out io.Writer, responseWriter http.ResponseWriter, src net.Conn) (int64, error) {
	if prime, err := relayTunnelPrimeDownload(src); err != nil {
		return 0, err
	} else if len(prime) > 0 {
		if _, err := out.Write(prime); err != nil {
			return int64(len(prime)), err
		}
		relayTunnelFlushNow(out, responseWriter)
	}
	bp := relayTunnelBufPool.Get().(*[]byte)
	defer relayTunnelBufPool.Put(bp)
	buf := *bp
	var written int64
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := out.Write(buf[:nr])
			written += int64(nw)
			if ew != nil {
				return written, ew
			}
			if nw < nr {
				return written, io.ErrShortWrite
			}
			relayTunnelFlushNow(out, responseWriter)
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

func relayTunnelFlushNow(out io.Writer, responseWriter http.ResponseWriter) {
	if fw, ok := out.(*relayTunnelFlushWriter); ok {
		fw.flushNow()
	}
	if rw, ok := out.(http.ResponseWriter); ok {
		_ = http.NewResponseController(rw).Flush()
	}
	if f, ok := responseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

type relayTunnelFlushWriter struct {
	w       io.Writer
	flusher http.Flusher
	pending int
}

func relayTunnelDownloadWriter(w io.Writer) io.Writer {
	if f, ok := w.(http.Flusher); ok {
		return &relayTunnelFlushWriter{w: w, flusher: f}
	}
	return w
}

func (f *relayTunnelFlushWriter) Write(p []byte) (int, error) {
	n, err := f.w.Write(p)
	if err != nil {
		return n, err
	}
	f.pending += n
	if f.pending >= 32*1024 {
		f.flushNow()
	}
	return n, nil
}

func (f *relayTunnelFlushWriter) flushNow() {
	if f.flusher != nil && f.pending > 0 {
		f.flusher.Flush()
		f.pending = 0
	}
}

func relayTCPTunnelH3Stream(ctx context.Context, targetConn net.Conn, reqBody io.ReadCloser, str *http3.Stream) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type closeWriter interface {
		CloseWrite() error
	}
	uploadSrc := relayTunnelUploadSource(reqBody, str)
	uploadErrCh := make(chan error, 1)
	downloadErrCh := make(chan error, 1)
	go func() {
		_, err := relayTunnelCopyBuffer(targetConn, uploadSrc)
		_ = reqBody.Close()
		if cw, ok := targetConn.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
		uploadErrCh <- err
	}()
	go func() {
		_, err := relayTunnelCopyBuffer(str, targetConn)
		downloadErrCh <- err
	}()
	return relayTunnelSelect(ctx, targetConn, reqBody, uploadErrCh, downloadErrCh)
}

// h3StreamFromCONNECTRelay prefers responseWriter hijack (thin server order), then req.Body.
func h3StreamFromCONNECTRelay(reqBody io.ReadCloser, responseWriter http.ResponseWriter) *http3.Stream {
	if os.Getenv("MASQUE_RELAY_LOG_HIJACK") == "1" {
		_, wHS := responseWriter.(http3.HTTPStreamer)
		_, bHS := reqBody.(http3.HTTPStreamer)
		fmt.Fprintf(os.Stderr, "masque relay hijack probe writer_httpstreamer=%v body_httpstreamer=%v\n", wHS, bHS)
	}
	if hs, ok := responseWriter.(http3.HTTPStreamer); ok {
		if str := hs.HTTPStream(); str != nil {
			return str
		}
	}
	if reqBody != nil {
		if hs, ok := reqBody.(http3.HTTPStreamer); ok {
			if str := hs.HTTPStream(); str != nil {
				if rel, ok := reqBody.(http3.ResponseStreamReleaser); ok {
					rel.ReleaseHTTPStream()
				}
				return str
			}
		}
	}
	return nil
}

func relayTunnelUploadSource(reqBody io.ReadCloser, str *http3.Stream) io.Reader {
	if str == nil {
		return reqBody
	}
	if reqBody == nil || reqBody == http.NoBody {
		return str
	}
	if RelayUploadFromStream() {
		return str
	}
	return reqBody
}

func relayTunnelCopyBuffer(dst io.Writer, src io.Reader) (int64, error) {
	bp := relayTunnelBufPool.Get().(*[]byte)
	defer relayTunnelBufPool.Put(bp)
	return io.CopyBuffer(dst, src, *bp)
}

func relayTunnelSelect(ctx context.Context, targetConn net.Conn, reqBody io.ReadCloser, uploadErrCh, downloadErrCh <-chan error) error {
	select {
	case <-ctx.Done():
		_ = targetConn.Close()
		uploadErr := <-uploadErrCh
		downloadErr := <-downloadErrCh
		return errors.Join(context.Cause(ctx), uploadErr, downloadErr)
	case uploadErr := <-uploadErrCh:
		if uploadErr != nil && !errors.Is(uploadErr, io.EOF) {
			_ = targetConn.Close()
			return uploadErr
		}
		select {
		case downloadErr := <-downloadErrCh:
			return relayTunnelJoinErrors(uploadErr, downloadErr)
		case <-ctx.Done():
			return context.Cause(ctx)
		}
	case downloadErr := <-downloadErrCh:
		if downloadErr != nil && !errors.Is(downloadErr, io.EOF) {
			_ = targetConn.Close()
			_ = reqBody.Close()
			return downloadErr
		}
		select {
		case uploadErr := <-uploadErrCh:
			return relayTunnelJoinErrors(uploadErr, downloadErr)
		case <-ctx.Done():
			return context.Cause(ctx)
		}
	}
}

func relayTunnelJoinErrors(uploadErr, downloadErr error) error {
	if uploadErr != nil && errors.Is(uploadErr, io.EOF) {
		uploadErr = nil
	}
	if downloadErr != nil && errors.Is(downloadErr, io.EOF) {
		downloadErr = nil
	}
	return errors.Join(uploadErr, downloadErr)
}
