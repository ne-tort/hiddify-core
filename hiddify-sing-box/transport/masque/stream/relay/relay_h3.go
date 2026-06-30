package relay

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/quic-go/quic-go/http3"
)

// relayDuplexArmUploadBytes avoids arming saturated duplex on iperf -R params (FAKEIPERF / cookie).
const relayDuplexArmUploadBytes = 4 * 1024

type relayH3UploadLegMode int

const (
	relayH3UploadLegNeutral relayH3UploadLegMode = iota
	relayH3UploadLegDownloadPrimary
)

func relayH3ProbeUploadLeg(uploadSrc io.Reader) (io.Reader, relayH3UploadLegMode, bool) {
	if uploadSrc == nil {
		return nil, relayH3UploadLegNeutral, false
	}
	useTimeout := false
	if d, ok := uploadSrc.(interface{ SetReadDeadline(time.Time) error }); ok {
		useTimeout = true
		_ = d.SetReadDeadline(time.Now().Add(3 * time.Millisecond))
	}
	one := make([]byte, 1)
	n, err := uploadSrc.Read(one)
	if useTimeout {
		if d, ok := uploadSrc.(interface{ SetReadDeadline(time.Time) error }); ok {
			_ = d.SetReadDeadline(time.Time{})
		}
	}
	if n > 0 {
		uploadStarted := !h2BootstrapUploadAllZero(one[:n])
		return io.MultiReader(bytes.NewReader(one[:n]), uploadSrc), relayH3UploadLegNeutral, uploadStarted
	}
	if errors.Is(err, io.EOF) {
		return uploadSrc, relayH3UploadLegDownloadPrimary, false
	}
	var ne net.Error
	if useTimeout && errors.As(err, &ne) && ne.Timeout() {
		return uploadSrc, relayH3UploadLegNeutral, false
	}
	return uploadSrc, relayH3UploadLegNeutral, false
}

func relayH3ProbeConcurrentUpload(uploadSrc io.Reader) (io.Reader, bool) {
	r, _, _ := relayH3ProbeUploadLeg(uploadSrc)
	return r, false
}

func relayTCPTunnelBidiStream(ctx context.Context, targetConn net.Conn, reqBody io.ReadCloser, bidi io.ReadWriteCloser) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type closeWriter interface {
		CloseWrite() error
	}
	uploadSrc := relayTunnelUploadSource(reqBody, bidi)
	uploadSrc, uploadLegMode, uploadStarted := relayH3ProbeUploadLeg(uploadSrc)
	if RelayUploadFromStream() && bidi != nil {
		uploadSrc = StripH3ClientBootstrapUpload(uploadSrc)
	}
	if w := relayBidiWakerFromRW(bidi); w != nil {
		if uploadLegMode == relayH3UploadLegDownloadPrimary || !uploadStarted {
			w.prepareDownloadPrimary()
		}
		w.enableDownloadSend()
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
	go func() {
		_, err := relayTunnelDownloadRelayH3Plain(bidi, targetConn)
		downloadErrCh <- err
	}()
	return relayTunnelSelect(ctx, targetConn, reqBody, uploadErrCh, downloadErrCh)
}

func relayTunnelDownloadRelayH3Plain(dst io.Writer, src net.Conn) (int64, error) {
	var written int64
	dstWaker := relayBidiWakerFromWriter(dst)
	if prime, err := relayTunnelPrimeDownload(src); err != nil {
		return 0, err
	} else if len(prime) > 0 {
		if _, err := dst.Write(prime); err != nil {
			return int64(len(prime)), err
		}
		written += int64(len(prime))
		if dstWaker != nil {
			_ = dstWaker.flushDownloadPrime()
		}
	}
	n, err := relayTunnelCopyBufferH3(dst, src)
	written += n
	if err != nil && !errors.Is(err, io.EOF) {
		return written, err
	}
	return written, nil
}

func relayTunnelCopyBufferH3(dst io.Writer, src io.Reader) (int64, error) {
	bp := relayTunnelBufPool.Get().(*[]byte)
	defer relayTunnelBufPool.Put(bp)
	buf := *bp
	var written int64
	var pendingWake int
	dstWaker := relayBidiWakerFromWriter(dst)
	wakeBatch := RelayTunnelFlushBytes
	if dstWaker != nil && !dstWaker.isDuplexUploadStarted() {
		wakeBatch = 4 * 1024
	}
	flushWake := func(w RelayBidiWaker) {
		if w == nil || pendingWake < wakeBatch {
			return
		}
		pendingWake = 0
		w.wakeAfterDownloadWrite()
	}
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			if nw > 0 {
				written += int64(nw)
				if dstWaker != nil {
					_ = dstWaker.flushCoalesce()
					if !dstWaker.isDuplexUploadStarted() {
						dstWaker.wakeAfterDownloadWrite()
					}
					pendingWake += nw
					flushWake(dstWaker)
				}
			}
			if ew != nil {
				if dstWaker != nil && pendingWake > 0 {
					pendingWake = 0
					dstWaker.wakeAfterDownloadWrite()
				}
				return written, ew
			}
			if nr != nw {
				return written, io.ErrShortWrite
			}
		}
		if er != nil {
			if dstWaker != nil && pendingWake > 0 {
				pendingWake = 0
				dstWaker.wakeAfterDownloadWrite()
			}
			if er == io.EOF {
				return written, nil
			}
			return written, er
		}
	}
}

func relayTunnelCopyBufferH3BidiUpload(dst io.Writer, src io.Reader, bidi io.ReadWriteCloser) (int64, error) {
	bp := relayTunnelBufPool.Get().(*[]byte)
	defer relayTunnelBufPool.Put(bp)
	buf := *bp
	var written int64
	var pendingWake int
	var uploadRelayTotal int
	var armDuplexOnce sync.Once
	bidiWaker := relayBidiWakerFromRW(bidi)
	armDuplexIfNeeded := func(w RelayBidiWaker, uploaded int) {
		if w == nil || uploaded <= 0 {
			return
		}
		uploadRelayTotal += uploaded
		if uploadRelayTotal < relayDuplexArmUploadBytes {
			return
		}
		armDuplexOnce.Do(func() {
			w.armDuplexParallel()
		})
	}
	flushWake := func(w RelayBidiWaker) {
		if w == nil || pendingWake < RelayTunnelUploadWakeBytes {
			return
		}
		pendingWake = 0
		w.wakeAfterUploadRead()
	}
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			if bidiWaker != nil {
				armDuplexIfNeeded(bidiWaker, nr)
				_ = bidiWaker.flushCoalesce()
			}
			nw, ew := dst.Write(buf[:nr])
			if nw > 0 {
				written += int64(nw)
				if bidiWaker != nil {
					pendingWake += nw
					flushWake(bidiWaker)
				}
			}
			if ew != nil {
				if bidiWaker != nil && pendingWake > 0 {
					pendingWake = 0
					bidiWaker.wakeAfterUploadRead()
				}
				return written, ew
			}
			if nr != nw {
				return written, io.ErrShortWrite
			}
		}
		if er != nil {
			if bidiWaker != nil && pendingWake > 0 {
				pendingWake = 0
				bidiWaker.wakeAfterUploadRead()
			}
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

func h3StreamFromCONNECTRelay(reqBody io.ReadCloser, responseWriter http.ResponseWriter) io.ReadWriteCloser {
	if p, ok := responseWriter.(RelayCONNECTH3Leg); ok {
		if leg := p.MasqueRelayCONNECTH3Leg(); leg != nil {
			masqueEnableRelayTunnelData(leg)
			return leg
		}
	}
	if hs, ok := responseWriter.(http3.HTTPStreamer); ok {
		if str := hs.HTTPStream(); str != nil {
			relayBidiWakerFromHTTPStream(str).enableConnectStream()
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
				relayBidiWakerFromHTTPStream(str).enableConnectStream()
				return str
			}
		}
	}
	return nil
}

func masqueEnableRelayTunnelData(leg io.ReadWriteCloser) {
	if w := relayBidiWakerFromRW(leg); w != nil {
		w.enableConnectStream()
	}
}
