package relay

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

const RelayTunnelBufLen = 64 * 1024

// RelayTunnelFlushBytes documents the load-bearing per-Write Flush quantum (= BufLen).
// Coalesce>BufLen without Flush is INCOMPATIBLE for H2 Extended CONNECT (field broke TTFB).
// WAN ~8 Mbit persists with large FC (ServerSendAvailMin≫65535) — not cured by Flush coalesce alone.
const RelayTunnelFlushBytes = RelayTunnelBufLen

var relayTunnelBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, RelayTunnelBufLen)
		return &b
	},
}

// relayTunnelPrimeDownload reads the first onward-TCP segment (iperf banner, etc.). Timeout with no bytes is OK.
// Implemented in relay_prime.go (opportunistic peek policy).

// Dead path note (H2-S4): relayTunnelDownloadWriter / batch flushWriter were never wired into
// RelayTCPTunnel (prod uses relayTunnelDownloadRelayH2 per-chunk Flush). Removed 2026-07-15.

func relayTunnelFlushFinal(out io.Writer, responseWriter http.ResponseWriter) {
	relayTunnelFlushNow(out, responseWriter)
}

func relayTunnelFlushNow(out io.Writer, responseWriter http.ResponseWriter) {
	// H2 full-duplex relay may flush after the CONNECT handler returns; http2 panics — ignore.
	defer func() { _ = recover() }()
	if rw, ok := out.(http.ResponseWriter); ok {
		_ = http.NewResponseController(rw).Flush()
	}
	if f, ok := responseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func relayTunnelUploadSource(reqBody io.ReadCloser, uploadLeg io.Reader) io.Reader {
	if uploadLeg != nil {
		return uploadLeg
	}
	return reqBody
}

func relayTunnelCopyBuffer(dst io.Writer, src io.Reader) (int64, error) {
	bp := relayTunnelBufPool.Get().(*[]byte)
	defer relayTunnelBufPool.Put(bp)
	return io.CopyBuffer(dst, src, *bp)
}

func relayTunnelUnblockPeerRead(conn net.Conn) {
	if d, ok := conn.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = d.SetReadDeadline(time.Now())
		_ = d.SetReadDeadline(time.Time{})
		return
	}
	_ = conn.Close()
}

func relayTunnelSelect(ctx context.Context, targetConn net.Conn, reqBody io.ReadCloser, uploadErrCh, downloadErrCh <-chan error, onAbort func()) error {
	select {
	case <-ctx.Done():
		if onAbort != nil {
			onAbort()
		}
		_ = targetConn.Close()
		uploadErr := <-uploadErrCh
		downloadErr := <-downloadErrCh
		return errors.Join(context.Cause(ctx), uploadErr, downloadErr)
	case uploadErr := <-uploadErrCh:
		if uploadErr != nil && !errors.Is(uploadErr, io.EOF) {
			if onAbort != nil {
				onAbort()
			}
			_ = targetConn.Close()
			downloadErr := <-downloadErrCh
			return relayTunnelJoinErrors(uploadErr, downloadErr)
		}
		relayTunnelUnblockPeerRead(targetConn)
		select {
		case downloadErr := <-downloadErrCh:
			return relayTunnelJoinErrors(uploadErr, downloadErr)
		case <-ctx.Done():
			if onAbort != nil {
				onAbort()
			}
			downloadErr := <-downloadErrCh
			return errors.Join(context.Cause(ctx), downloadErr)
		}
	case downloadErr := <-downloadErrCh:
		if downloadErr != nil && !errors.Is(downloadErr, io.EOF) {
			if onAbort != nil {
				onAbort()
			}
			_ = targetConn.Close()
			if reqBody != nil {
				_ = reqBody.Close()
			}
			uploadErr := <-uploadErrCh
			return relayTunnelJoinErrors(uploadErr, downloadErr)
		}
		select {
		case uploadErr := <-uploadErrCh:
			return relayTunnelJoinErrors(uploadErr, downloadErr)
		case <-ctx.Done():
			if onAbort != nil {
				onAbort()
			}
			uploadErr := <-uploadErrCh
			return errors.Join(context.Cause(ctx), uploadErr)
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
