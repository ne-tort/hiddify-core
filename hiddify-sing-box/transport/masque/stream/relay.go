package stream

import (
	_ "embed"
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

//go:embed relay.go
var relayGoAuditSource string

// RelayGoAuditSource returns relay.go source for frozen delegate audits (REF-SRC-THIN-2).
func RelayGoAuditSource() string { return relayGoAuditSource }

const RelayTunnelBufLen = 64 * 1024

// RelayTunnelFlushBytes is the H2 EnableFullDuplex batch flush threshold (h2o proxy.tunnel parity).
const RelayTunnelFlushBytes = RelayTunnelBufLen

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

// RelayCONNECTH3Leg injects an HTTP/3 bidi relay leg for in-process tests (S37) without a live QUIC stack.
type RelayCONNECTH3Leg interface {
	MasqueRelayCONNECTH3Leg() io.ReadWriteCloser
}

// RelayTCPTunnel relays CONNECT tunneled TCP like h2o proxy.tunnel (64 KiB io.CopyBuffer, full duplex).
func RelayTCPTunnel(ctx context.Context, targetConn net.Conn, reqBody io.ReadCloser, responseWriter http.ResponseWriter) error {
	if RelayUseHTTP3StreamHijack() {
		if leg := h3StreamFromCONNECTRelay(reqBody, responseWriter); leg != nil {
			// Parity h3.TunnelConn: release CONNECT req.Body after hijack so http3 request
			// bookkeeping does not stall bidi relay (responseWriter or reqBody path).
			releaseConnectRelayRequestBody(reqBody)
			return relayTCPTunnelBidiStream(ctx, targetConn, reqBody, leg)
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

// relayTunnelDownloadRelay copies onward TCP → CONNECT response; H2 path primes iperf banner
// then bulk-copies with io.CopyBuffer (64 KiB, h2o proxy.tunnel parity) and batch flush at EOF.
func relayTunnelDownloadRelay(out io.Writer, responseWriter http.ResponseWriter, src net.Conn) (int64, error) {
	bp := relayTunnelBufPool.Get().(*[]byte)
	defer relayTunnelBufPool.Put(bp)
	buf := *bp
	var written int64
	if prime, err := relayTunnelPrimeDownload(src); err != nil {
		return 0, err
	} else if len(prime) > 0 {
		if _, err := out.Write(prime); err != nil {
			return int64(len(prime)), err
		}
		written += int64(len(prime))
		// H2 EnableFullDuplex: small iperf banner must reach the client download drain
		// before onward TCP blocks on upload-only targets (connect-stream-h2 docker hang).
		relayTunnelFlushFinal(out, responseWriter)
	}
	n, err := io.CopyBuffer(out, src, buf)
	written += n
	if err != nil && !errors.Is(err, io.EOF) {
		return written, err
	}
	relayTunnelFlushFinal(out, responseWriter)
	return written, nil
}

func relayTunnelFlushFinal(out io.Writer, responseWriter http.ResponseWriter) {
	if fw, ok := out.(*relayTunnelFlushWriter); ok {
		fw.flushNow()
		return
	}
	relayTunnelFlushNow(out, responseWriter)
}

func relayTunnelFlushNow(out io.Writer, responseWriter http.ResponseWriter) {
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
	if f.pending >= RelayTunnelFlushBytes {
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

// RelayTCPTunnelBidiStream runs the HTTP/3 hijack relay path (io.CopyBuffer both halves, no H2 per-read flush).
// Used by RelayTCPTunnel when HTTPStreamer hijacks *http3.Stream; also for in-proc localize benches.
func RelayTCPTunnelBidiStream(ctx context.Context, targetConn net.Conn, reqBody io.ReadCloser, bidi io.ReadWriteCloser) error {
	return relayTCPTunnelBidiStream(ctx, targetConn, reqBody, bidi)
}

// RelayTunnelDownloadH2Style copies onward TCP → CONNECT response with batched 64 KiB flush (H2 EnableFullDuplex path).
func RelayTunnelDownloadH2Style(out io.Writer, responseWriter http.ResponseWriter, src net.Conn) (int64, error) {
	return relayTunnelDownloadRelay(out, responseWriter, src)
}

// relayTCPTunnelBidiStream is the H3 hijack relay: full-duplex io.CopyBuffer on the QUIC stream leg.
// Per-read HTTP flush (relayTunnelDownloadRelay) is intentionally omitted — QUIC stream framing delivers
// download data without H2 ResponseWriter batching; docker ~130 down on connect-stream-h3 is client bidi credit.
func relayTCPTunnelBidiStream(ctx context.Context, targetConn net.Conn, reqBody io.ReadCloser, bidi io.ReadWriteCloser) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type closeWriter interface {
		CloseWrite() error
	}
	uploadSrc := relayTunnelUploadSource(reqBody, bidi)
	uploadErrCh := make(chan error, 1)
	downloadErrCh := make(chan error, 1)
	// Mark download-active before both relay goroutines so upload reads get framer
	// bidi-boost + eager WINDOW poke from the first chunk (race: upload started first).
	if bidi != nil {
		relayTunnelSetBidiDownloadActive(bidi, true)
		defer relayTunnelSetBidiDownloadActive(bidi, false)
	}
	go func() {
		var err error
		if RelayBidiDownloadWriteWakeEnabled() && bidi != nil {
			_, err = relayTunnelCopyBufferBidiUpload(targetConn, uploadSrc, bidi)
		} else {
			_, err = relayTunnelCopyBuffer(targetConn, uploadSrc)
		}
		_ = reqBody.Close()
		if cw, ok := targetConn.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
		uploadErrCh <- err
	}()
	go func() {
		_, err := relayTunnelCopyBufferBidiDownload(bidi, targetConn, bidi)
		downloadErrCh <- err
	}()
	return relayTunnelSelect(ctx, targetConn, reqBody, uploadErrCh, downloadErrCh)
}

func releaseConnectRelayRequestBody(reqBody io.ReadCloser) {
	if reqBody == nil || reqBody == http.NoBody {
		return
	}
	if rel, ok := reqBody.(http3.ResponseStreamReleaser); ok {
		rel.ReleaseHTTPStream()
	}
}

// h3StreamFromCONNECTRelay prefers responseWriter hijack (thin server order), then req.Body.
func h3StreamFromCONNECTRelay(reqBody io.ReadCloser, responseWriter http.ResponseWriter) io.ReadWriteCloser {
	if os.Getenv("MASQUE_RELAY_LOG_HIJACK") == "1" {
		_, wHS := responseWriter.(http3.HTTPStreamer)
		_, bHS := reqBody.(http3.HTTPStreamer)
		fmt.Fprintf(os.Stderr, "masque relay hijack probe writer_httpstreamer=%v body_httpstreamer=%v\n", wHS, bHS)
	}
	if p, ok := responseWriter.(RelayCONNECTH3Leg); ok {
		if leg := p.MasqueRelayCONNECTH3Leg(); leg != nil {
			return leg
		}
	}
	if hs, ok := responseWriter.(http3.HTTPStreamer); ok {
		if str := hs.HTTPStream(); str != nil {
			return str
		}
	}
	if reqBody != nil {
		if p, ok := reqBody.(RelayCONNECTH3Leg); ok {
			if leg := p.MasqueRelayCONNECTH3Leg(); leg != nil {
				return leg
			}
		}
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

func relayTunnelUploadSource(reqBody io.ReadCloser, uploadLeg io.Reader) io.Reader {
	if uploadLeg == nil {
		return reqBody
	}
	if reqBody == nil || reqBody == http.NoBody {
		return uploadLeg
	}
	if RelayUploadFromStream() {
		return uploadLeg
	}
	return reqBody
}

func relayTunnelCopyBuffer(dst io.Writer, src io.Reader) (int64, error) {
	bp := relayTunnelBufPool.Get().(*[]byte)
	defer relayTunnelBufPool.Put(bp)
	return io.CopyBuffer(dst, src, *bp)
}

// relayTunnelCopyBufferBidiUpload copies client upload → onward TCP with per-chunk bidi wake
// so download halves stay scheduled during server upload drain (prod STREAM_HIJACK path).
func relayTunnelCopyBufferBidiUpload(dst io.Writer, src io.Reader, bidi any) (int64, error) {
	bp := relayTunnelBufPool.Get().(*[]byte)
	defer relayTunnelBufPool.Put(bp)
	buf := *bp
	var written int64
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			if nw > 0 {
				written += int64(nw)
				relayTunnelWakeBidiAfterUploadRead(bidi)
			}
			if ew != nil {
				return written, ew
			}
			if nr != nw {
				return written, io.ErrShortWrite
			}
		}
		if er != nil {
			if er == io.EOF {
				return written, nil
			}
			return written, er
		}
	}
}

// relayTunnelCopyBufferBidiDownload copies onward TCP → hijacked H3 stream with per-chunk
// bidi wake so upload halves stay scheduled during server download (prod STREAM_HIJACK path).
func relayTunnelCopyBufferBidiDownload(dst io.Writer, src io.Reader, bidi any) (int64, error) {
	bp := relayTunnelBufPool.Get().(*[]byte)
	defer relayTunnelBufPool.Put(bp)
	buf := *bp
	var written int64
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			if nw > 0 {
				written += int64(nw)
				relayTunnelWakeBidiAfterDownloadWrite(bidi)
			}
			if ew != nil {
				return written, ew
			}
			if nr != nw {
				return written, io.ErrShortWrite
			}
		}
		if er != nil {
			if er == io.EOF {
				return written, nil
			}
			return written, er
		}
	}
}

// relayTunnelUnblockPeerRead nudges a blocked download relay when the upload half finished
// with EOF and the onward TCP peer is idle (upload-only workloads, discard iperf targets).
func relayTunnelUnblockPeerRead(conn net.Conn) {
	if d, ok := conn.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = d.SetReadDeadline(time.Now())
		return
	}
	_ = conn.Close()
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
		relayTunnelUnblockPeerRead(targetConn)
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
