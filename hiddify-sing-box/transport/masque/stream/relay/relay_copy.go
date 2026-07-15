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

// RelayTunnelBufLen is the CONNECT-stream relay CopyBuffer / Flush quantum.
// Field CF __down stop-wait ≈ BufLen×8/RTT: 256 KiB→~54, 1 MiB→~267 @30 ms.
// 4 MiB lifts ceiling above path (~1 Gbit @30 ms) while fill-then-Flush still
// does one Flush per filled buffer (not S3 Flush-less coalesce).
const RelayTunnelBufLen = 4 << 20

// RelayTunnelFlushBytes is an alias kept for arch/docs (= BufLen; per-Write Flush).
const RelayTunnelFlushBytes = RelayTunnelBufLen

var relayTunnelBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, RelayTunnelBufLen)
		return &b
	},
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
