package stream

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/quic-go/quic-go/http3"
)

//go:embed relay.go
var relayGoAuditSource string

// RelayGoAuditSource returns relay.go source for frozen delegate audits (REF-SRC-THIN-2).
func RelayGoAuditSource() string { return relayGoAuditSource }

const RelayTunnelBufLen = 256 * 1024

// RelayTunnelFlushBytes is the H2 EnableFullDuplex batch flush threshold (h2o proxy.tunnel parity).
const RelayTunnelFlushBytes = RelayTunnelBufLen

var relayTunnelBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, RelayTunnelBufLen)
		return &b
	},
}

// RelayUseHTTP3StreamHijack enables hijacked *http3.Stream relay (prod always on).
func RelayUseHTTP3StreamHijack() bool { return true }

// RelayUploadFromStream reads client upload from the hijacked HTTP/3 stream (prod always on).
func RelayUploadFromStream() bool { return true }

// RelayCONNECTH3Leg injects an HTTP/3 bidi relay leg for in-process tests (S37) without a live QUIC stack.
type RelayCONNECTH3Leg interface {
	MasqueRelayCONNECTH3Leg() io.ReadWriteCloser
}

// RelayTCPTunnel relays CONNECT tunneled TCP like h2o proxy.tunnel (plain io.CopyBuffer, full duplex).
func RelayTCPTunnel(ctx context.Context, targetConn net.Conn, reqBody io.ReadCloser, responseWriter http.ResponseWriter, legRole string) error {
	_ = legRole
	if leg := h3StreamFromCONNECTRelay(reqBody, responseWriter); leg != nil {
		releaseConnectRelayRequestBody(reqBody)
		return relayTCPTunnelBidiStream(ctx, targetConn, reqBody, leg)
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
		_, err := relayTunnelCopyBufferH2BidiUpload(targetConn, StripH2ClientBootstrapUpload(reqBody), responseWriter)
		_ = reqBody.Close()
		if cw, ok := targetConn.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
		uploadErrCh <- err
	}()
	go func() {
		out := relayTunnelDownloadWriter(responseWriter)
		_, err := relayTunnelDownloadRelayH2(out, responseWriter, targetConn)
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

// relayTunnelDownloadRelayH2 copies onward TCP → CONNECT response with per-chunk H2 flush so
// client download reads and upload FC stay interleaved during iperf -R duplex.
func relayTunnelDownloadRelayH2(out io.Writer, responseWriter http.ResponseWriter, src net.Conn) (int64, error) {
	var written int64
	if prime, err := relayTunnelPrimeDownload(src); err != nil {
		return 0, err
	} else if len(prime) > 0 {
		if _, err := out.Write(prime); err != nil {
			return int64(len(prime)), err
		}
		written += int64(len(prime))
		relayTunnelFlushFinal(out, responseWriter)
	}
	n, err := relayTunnelCopyBufferH2BidiDownload(out, src, responseWriter)
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

// RelayTCPTunnelBidiStream runs the HTTP/3 hijack relay path (h2o plain io.CopyBuffer both halves).
func RelayTCPTunnelBidiStream(ctx context.Context, targetConn net.Conn, reqBody io.ReadCloser, bidi io.ReadWriteCloser) error {
	return relayTCPTunnelBidiStream(ctx, targetConn, reqBody, bidi)
}

// RelayTunnelDownloadH2Style copies onward TCP → CONNECT response with batched H2 flush (fallback path).
func RelayTunnelDownloadH2Style(out io.Writer, responseWriter http.ResponseWriter, src net.Conn) (int64, error) {
	return relayTunnelDownloadRelay(out, responseWriter, src)
}

// relayTCPTunnelBidiStream is the prod H3 hijack relay: full-duplex plain io.CopyBuffer on one bidi stream.
func relayTCPTunnelBidiStream(ctx context.Context, targetConn net.Conn, reqBody io.ReadCloser, bidi io.ReadWriteCloser) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if str, ok := bidi.(*http3.Stream); ok {
		http3.ArmMasqueBidiDuplexFair(str)
	}
	type closeWriter interface {
		CloseWrite() error
	}
	uploadSrc := relayTunnelUploadSource(reqBody, bidi)
	if RelayUploadFromStream() && bidi != nil {
		uploadSrc = StripH3ClientBootstrapUpload(uploadSrc)
	}
	uploadErrCh := make(chan error, 1)
	downloadErrCh := make(chan error, 1)
	go func() {
		_, err := relayTunnelCopyBufferH3BidiUpload(targetConn, uploadSrc, bidi)
		_ = reqBody.Close()
		if cw, ok := targetConn.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
		uploadErrCh <- err
	}()
	if str, ok := bidi.(*http3.Stream); ok {
		http3.WaitMasqueRelayPeerUploadCredit(str)
		http3.EnableMasqueRelayDownloadSend(str)
	}
	go func() {
		_, err := relayTunnelDownloadRelayH3Plain(bidi, targetConn)
		downloadErrCh <- err
	}()
	return relayTunnelSelect(ctx, targetConn, reqBody, uploadErrCh, downloadErrCh)
}

// relayTunnelDownloadRelayH3Plain copies onward TCP → hijacked H3 stream with iperf banner prime
// then plain io.CopyBuffer (h2o proxy.tunnel parity, no per-chunk wake).
func relayTunnelDownloadRelayH3Plain(dst io.Writer, src net.Conn) (int64, error) {
	var written int64
	if prime, err := relayTunnelPrimeDownload(src); err != nil {
		return 0, err
	} else if len(prime) > 0 {
		if _, err := dst.Write(prime); err != nil {
			return int64(len(prime)), err
		}
		written += int64(len(prime))
		if str, ok := dst.(*http3.Stream); ok {
			_ = http3.FlushMasqueRelayDownloadPrime(str)
		}
	}
	n, err := relayTunnelCopyBufferH3(dst, src)
	written += n
	if err != nil && !errors.Is(err, io.EOF) {
		return written, err
	}
	return written, nil
}

// relayTunnelCopyBufferH3 copies onward TCP → hijacked H3 stream with per-chunk coalesce flush
// (small iperf banner + short bulk must not wait for 256 KiB coalesce).
func relayTunnelCopyBufferH3(dst io.Writer, src io.Reader) (int64, error) {
	bp := relayTunnelBufPool.Get().(*[]byte)
	defer relayTunnelBufPool.Put(bp)
	buf := *bp
	readLen := len(buf)
	if str, ok := dst.(*http3.Stream); ok && http3.IsMasqueBidiDuplexUploadStarted(str) {
		readLen = 64 * 1024
	}
	var written int64
	for {
		nr, er := src.Read(buf[:readLen])
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			if nw > 0 {
				written += int64(nw)
				if str, ok := dst.(*http3.Stream); ok {
					_ = str.FlushMasqueCoalesce()
					http3.WakeMasqueRelayAfterDownloadWrite(str)
				}
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

// relayTunnelCopyBufferH3BidiUpload copies client upload → onward TCP with per-chunk duplex mark + wake.
func relayTunnelCopyBufferH3BidiUpload(dst io.Writer, src io.Reader, bidi io.ReadWriteCloser) (int64, error) {
	bp := relayTunnelBufPool.Get().(*[]byte)
	defer relayTunnelBufPool.Put(bp)
	buf := *bp
	var written int64
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			if str, ok := bidi.(*http3.Stream); ok {
				_ = str.FlushMasqueCoalesce()
				http3.WakeMasqueRelayAfterUploadRead(str)
			}
			nw, ew := dst.Write(buf[:nr])
			if nw > 0 {
				written += int64(nw)
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

func releaseConnectRelayRequestBody(reqBody io.ReadCloser) {
	if reqBody == nil || reqBody == http.NoBody {
		return
	}
	if rel, ok := reqBody.(http3.ResponseStreamReleaser); ok {
		rel.ReleaseHTTPStream()
	}
}

// h3StreamFromCONNECTRelay prefers responseWriter hijack (H3 CONNECT order), then req.Body.
func h3StreamFromCONNECTRelay(reqBody io.ReadCloser, responseWriter http.ResponseWriter) io.ReadWriteCloser {
	if os.Getenv("MASQUE_RELAY_LOG_HIJACK") == "1" {
		_, wHS := responseWriter.(http3.HTTPStreamer)
		_, bHS := reqBody.(http3.HTTPStreamer)
		fmt.Fprintf(os.Stderr, "masque relay hijack probe writer_httpstreamer=%v body_httpstreamer=%v\n", wHS, bHS)
	}
	if p, ok := responseWriter.(RelayCONNECTH3Leg); ok {
		if leg := p.MasqueRelayCONNECTH3Leg(); leg != nil {
			masqueEnableRelayTunnelData(leg)
			return leg
		}
	}
	if hs, ok := responseWriter.(http3.HTTPStreamer); ok {
		if str := hs.HTTPStream(); str != nil {
			http3.EnableMasqueConnectStream(str)
			return str
		}
	}
	if reqBody != nil {
		if p, ok := reqBody.(RelayCONNECTH3Leg); ok {
			if leg := p.MasqueRelayCONNECTH3Leg(); leg != nil {
				masqueEnableRelayTunnelData(leg)
				return leg
			}
		}
		if hs, ok := reqBody.(http3.HTTPStreamer); ok {
			if str := hs.HTTPStream(); str != nil {
				if rel, ok := reqBody.(http3.ResponseStreamReleaser); ok {
					rel.ReleaseHTTPStream()
				}
				http3.EnableMasqueConnectStream(str)
				return str
			}
		}
	}
	return nil
}

func masqueEnableRelayTunnelData(leg io.ReadWriteCloser) {
	if str, ok := leg.(*http3.Stream); ok {
		http3.EnableMasqueConnectStream(str)
	}
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
