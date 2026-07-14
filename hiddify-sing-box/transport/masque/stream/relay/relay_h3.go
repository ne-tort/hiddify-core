package relay

import (
	"context"
	"io"
	"net"
	"net/http"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func relayEnableH3ConnectStream(leg io.ReadWriteCloser) {
	if str, ok := leg.(*http3.Stream); ok {
		http3.EnableMasqueConnectStream(str)
	}
}

func releaseH3ConnectRelayStream(bidi io.ReadWriteCloser) {
	if bidi == nil {
		return
	}
	// http3.Server non-hijack path always CancelRead+Close. Hijacked CONNECT must mirror that:
	// stream.Close() alone only finishes the send half; without CancelRead (or Read-to-EOF)
	// the server receive half never onStreamCompleted → MaxIncomingStreams slot stays ghosted.
	const code = quic.StreamErrorCode(http3.ErrCodeRequestCanceled)
	type cancelReader interface {
		CancelRead(quic.StreamErrorCode)
	}
	if cr, ok := bidi.(cancelReader); ok {
		cr.CancelRead(code)
	}
	_ = bidi.Close()
}

func abortH3ConnectRelayReceive(bidi io.ReadWriteCloser) {
	if bidi == nil {
		return
	}
	const code = quic.StreamErrorCode(http3.ErrCodeRequestCanceled)
	type cancelReader interface {
		CancelRead(quic.StreamErrorCode)
	}
	if cr, ok := bidi.(cancelReader); ok {
		cr.CancelRead(code)
	}
}

func relayTCPTunnelBidiStream(ctx context.Context, targetConn net.Conn, reqBody io.ReadCloser, bidi io.ReadWriteCloser) error {
	if bidi != nil {
		defer releaseH3ConnectRelayStream(bidi)
	}
	relayEnableH3ConnectStream(bidi)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type closeWriter interface {
		CloseWrite() error
	}
	uploadSrc := relayTunnelUploadSource(reqBody, bidi)
	uploadErrCh := make(chan error, 1)
	downloadErrCh := make(chan error, 1)
	go func() {
		_, err := relayTunnelCopyBufferH3Upload(targetConn, uploadSrc)
		if cw, ok := targetConn.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
		uploadErrCh <- err
	}()
	go func() {
		_, err := relayTunnelDownloadRelayH3(bidi, targetConn)
		downloadErrCh <- err
	}()
	return relayTunnelSelect(ctx, targetConn, nil, uploadErrCh, downloadErrCh, func() {
		abortH3ConnectRelayReceive(bidi)
	})
}

func relayTunnelCopyBufferH3Plain(dst io.Writer, src io.Reader) (int64, error) {
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

func relayTunnelCopyBufferH3Upload(dst io.Writer, src io.Reader) (int64, error) {
	return relayTunnelCopyBufferH3Plain(dst, src)
}

func relayTunnelDownloadRelayH3(dst io.Writer, src net.Conn) (int64, error) {
	var written int64
	if prime, err := relayTunnelPrimeDownload(src); err != nil {
		return 0, err
	} else if len(prime) > 0 {
		if _, err := dst.Write(prime); err != nil {
			return int64(len(prime)), err
		}
		written += int64(len(prime))
	}
	n, err := relayTunnelCopyBufferH3Plain(dst, src)
	written += n
	if err != nil && err != io.EOF {
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

func h3StreamFromCONNECTRelay(reqBody io.ReadCloser, responseWriter http.ResponseWriter) io.ReadWriteCloser {
	if p, ok := responseWriter.(RelayCONNECTH3Leg); ok {
		if leg := p.MasqueRelayCONNECTH3Leg(); leg != nil {
			relayEnableH3ConnectStream(leg)
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
				relayEnableH3ConnectStream(leg)
				return leg
			}
		}
		if hs, ok := reqBody.(http3.HTTPStreamer); ok {
			if str := hs.HTTPStream(); str != nil {
				http3.EnableMasqueConnectStream(str)
				return str
			}
		}
	}
	return nil
}
