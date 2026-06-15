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

// RelayTCPTunnel relays CONNECT tunneled TCP like h2o proxy.tunnel (64 KiB io.CopyBuffer, full duplex).
// legRole is optional P2/P6 leg (ConnectStreamLegUpload / ConnectStreamLegDownload); "" = single bidi.
func RelayTCPTunnel(ctx context.Context, targetConn net.Conn, reqBody io.ReadCloser, responseWriter http.ResponseWriter, legRole string) error {
	policy := CurrentRelayTCPPolicy(legRole)
	if policy.UseHijackRelay() {
		if leg := h3StreamFromCONNECTRelay(reqBody, responseWriter); leg != nil {
			// Parity h3.TunnelConn: release CONNECT req.Body after hijack so http3 request
			// bookkeeping does not stall bidi relay (responseWriter or reqBody path).
			releaseConnectRelayRequestBody(reqBody)
			return relayTCPTunnelBidiStream(ctx, targetConn, reqBody, leg, legRole, policy)
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

// RelayTCPTunnelBidiStream runs the HTTP/3 hijack relay path (io.CopyBuffer both halves, no H2 per-read flush).
// Used by RelayTCPTunnel when HTTPStreamer hijacks *http3.Stream; also for in-proc localize benches.
func RelayTCPTunnelBidiStream(ctx context.Context, targetConn net.Conn, reqBody io.ReadCloser, bidi io.ReadWriteCloser) error {
	return relayTCPTunnelBidiStream(ctx, targetConn, reqBody, bidi, "", CurrentRelayTCPPolicy(""))
}

// RelayTunnelDownloadH2Style copies onward TCP → CONNECT response with batched 64 KiB flush (H2 EnableFullDuplex path).
func RelayTunnelDownloadH2Style(out io.Writer, responseWriter http.ResponseWriter, src net.Conn) (int64, error) {
	return relayTunnelDownloadRelay(out, responseWriter, src)
}

// relayTCPTunnelBidiStream is the H3 hijack relay: full-duplex io.CopyBuffer on the QUIC stream leg.
// Per-read HTTP flush (relayTunnelDownloadRelay) is intentionally omitted — QUIC stream framing delivers
// download data without H2 ResponseWriter batching; docker ~130 down on connect-stream-h3 is client bidi credit.
// P6 upload leg (legRole=upload): discard target download at server — do not pump bulk S2C on upload QUIC conn.
func relayTCPTunnelBidiStream(ctx context.Context, targetConn net.Conn, reqBody io.ReadCloser, bidi io.ReadWriteCloser, legRole string, policy RelayTCPPolicy) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type closeWriter interface {
		CloseWrite() error
	}
	uploadLegOnly := legRole == ConnectStreamLegUpload
	uploadSrc := relayTunnelUploadSource(reqBody, bidi)
	if RelayUploadFromStream() && bidi != nil {
		uploadSrc = StripH3ClientBootstrapUpload(uploadSrc)
	}
	uploadErrCh := make(chan error, 1)
	downloadErrCh := make(chan error, 1)
	if bidi != nil && policy.UseSchedulerBoost() {
		if uploadLegOnly {
			relayTunnelSetBidiUploadActive(bidi, true)
			defer relayTunnelSetBidiUploadActive(bidi, false)
		} else {
			relayTunnelSetBidiDownloadActive(bidi, true)
			defer relayTunnelSetBidiDownloadActive(bidi, false)
		}
	}
	go func() {
		var err error
		switch {
		case uploadLegOnly && bidi != nil && policy.UsePerChunkWake():
			_, err = relayTunnelCopyBufferBidiUploadLeg(targetConn, uploadSrc, bidi)
		case policy.UsePerChunkWake() && bidi != nil:
			_, err = relayTunnelCopyBufferBidiUpload(targetConn, uploadSrc, bidi)
		case policy.UseBatchedDuplexWake() && bidi != nil:
			_, err = relayTunnelCopyBufferBatched(targetConn, uploadSrc, func() { relayTunnelWakeBatchedDuplexUpload(bidi) })
		default:
			_, err = relayTunnelCopyBuffer(targetConn, uploadSrc)
		}
		_ = reqBody.Close()
		if cw, ok := targetConn.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
		uploadErrCh <- err
	}()
	go func() {
		var err error
		if uploadLegOnly {
			// Drain target bulk on upload CONNECT so upload relay is not QUIC-flooded; discard locally.
			_, err = relayTunnelCopyBuffer(io.Discard, targetConn)
		} else if policy.UsePerChunkWake() {
			_, err = relayTunnelDownloadRelayH3Bidi(bidi, targetConn, bidi, legRole == ConnectStreamLegDownload)
		} else if policy.UseBatchedDuplexWake() {
			_, err = relayTunnelDownloadRelayH3Batched(bidi, targetConn, bidi)
		} else {
			_, err = relayTunnelDownloadRelayH3Plain(bidi, targetConn)
		}
		downloadErrCh <- err
	}()
	return relayTunnelSelect(ctx, targetConn, reqBody, uploadErrCh, downloadErrCh)
}

// relayTunnelDownloadRelayH3Batched copies onward TCP → hijacked H3 stream with iperf prime
// then plain copy with 64 KiB batched bidi wake (thin single-bidi duplex).
func relayTunnelDownloadRelayH3Batched(dst io.Writer, src net.Conn, bidi any) (int64, error) {
	var written int64
	if prime, err := relayTunnelPrimeDownload(src); err != nil {
		return 0, err
	} else if len(prime) > 0 {
		if _, err := dst.Write(prime); err != nil {
			return int64(len(prime)), err
		}
		written += int64(len(prime))
		relayTunnelWakeBatchedDuplex(bidi)
	}
	n, err := relayTunnelCopyBufferBatched(dst, src, func() { relayTunnelWakeBatchedDuplex(bidi) })
	written += n
	if err != nil && !errors.Is(err, io.EOF) {
		return written, err
	}
	return written, nil
}

// relayTunnelCopyBufferBatched copies with optional wake every RelayTunnelFlushBytes.
func relayTunnelCopyBufferBatched(dst io.Writer, src io.Reader, wake func()) (int64, error) {
	bp := relayTunnelBufPool.Get().(*[]byte)
	defer relayTunnelBufPool.Put(bp)
	buf := *bp
	var written int64
	var pending int64
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			if nw > 0 {
				written += int64(nw)
				if wake != nil {
					pending += int64(nw)
					if pending >= RelayTunnelFlushBytes {
						pending = 0
						wake()
					}
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

// relayTunnelDownloadRelayH3Plain copies onward TCP → hijacked H3 stream with iperf banner prime
// then plain io.CopyBuffer (thin prod path, no per-chunk wake).
func relayTunnelDownloadRelayH3Plain(dst io.Writer, src net.Conn) (int64, error) {
	var written int64
	if prime, err := relayTunnelPrimeDownload(src); err != nil {
		return 0, err
	} else if len(prime) > 0 {
		if _, err := dst.Write(prime); err != nil {
			return int64(len(prime)), err
		}
		written += int64(len(prime))
	}
	n, err := relayTunnelCopyBuffer(dst, src)
	written += n
	if err != nil && !errors.Is(err, io.EOF) {
		return written, err
	}
	return written, nil
}

// relayTunnelDownloadRelayH3Bidi copies onward TCP → hijacked H3 stream with iperf banner prime
// (parity relayTunnelDownloadRelayH2) then per-chunk bidi wake during bulk download.
func relayTunnelDownloadRelayH3Bidi(dst io.Writer, src net.Conn, bidi any, s2cSenderLeg bool) (int64, error) {
	var written int64
	wakeAfterDownload := relayTunnelWakeBidiAfterDownloadWrite
	if s2cSenderLeg {
		// P2 download CONNECT: per-chunk conn wake after S2C Write (H3-L1c-9); full duplex wake
		// starves sibling upload C2S when both legs share QUIC conn (H3-L1c-7f).
		wakeAfterDownload = relayTunnelWakeBidiSendOnly
	}
	if prime, err := relayTunnelPrimeDownload(src); err != nil {
		return 0, err
	} else if len(prime) > 0 {
		if _, err := dst.Write(prime); err != nil {
			return int64(len(prime)), err
		}
		written += int64(len(prime))
		wakeAfterDownload(bidi)
	}
	n, err := relayTunnelCopyBufferBidiDownload(dst, src, bidi, wakeAfterDownload)
	written += n
	if err != nil && !errors.Is(err, io.EOF) {
		return written, err
	}
	return written, nil
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
func relayTunnelCopyBufferBidiDownload(dst io.Writer, src io.Reader, bidi any, wakeAfterDownload func(any)) (int64, error) {
	if wakeAfterDownload == nil {
		wakeAfterDownload = relayTunnelWakeBidiAfterDownloadWrite
	}
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
				wakeAfterDownload(bidi)
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
