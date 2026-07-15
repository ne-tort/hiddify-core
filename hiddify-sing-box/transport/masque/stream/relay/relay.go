package relay

import (
	"context"
	"io"
	"net"
	"net/http"
)

// RelayCONNECTH3Leg injects an HTTP/3 bidi relay leg for in-process tests (S37) without a live QUIC stack.
type RelayCONNECTH3Leg interface {
	MasqueRelayCONNECTH3Leg() io.ReadWriteCloser
}

// RelayTCPTunnel relays CONNECT tunneled TCP like h2o proxy.tunnel (plain io.CopyBuffer, full duplex).
func RelayTCPTunnel(ctx context.Context, targetConn net.Conn, reqBody io.ReadCloser, responseWriter http.ResponseWriter) error {
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
		_, err := relayTunnelCopyBufferH2BidiUpload(targetConn, StripH2ClientBootstrapUpload(reqBody))
		_ = reqBody.Close()
		if cw, ok := targetConn.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
		uploadErrCh <- err
	}()
	go func() {
		_, err := relayTunnelDownloadRelayH2(responseWriter, responseWriter, targetConn)
		downloadErrCh <- err
	}()
	// H2-L5: mirror H3 abortH3ConnectRelayReceive — unblock upload Read on ctx/peer abort.
	onAbort := func() {
		if reqBody != nil {
			_ = reqBody.Close()
		}
	}
	return relayTunnelSelect(ctx, targetConn, reqBody, uploadErrCh, downloadErrCh, onAbort)
}

// RelayTCPTunnelBidiStream runs the HTTP/3 hijack relay path (h2o plain io.CopyBuffer both halves).
func RelayTCPTunnelBidiStream(ctx context.Context, targetConn net.Conn, reqBody io.ReadCloser, bidi io.ReadWriteCloser) error {
	return relayTCPTunnelBidiStream(ctx, targetConn, reqBody, bidi)
}

// RelayTunnelDownloadH2 copies onward TCP → CONNECT response with prod H2 per-chunk Flush.
func RelayTunnelDownloadH2(out io.Writer, responseWriter http.ResponseWriter, src net.Conn) (int64, error) {
	return relayTunnelDownloadRelayH2(out, responseWriter, src)
}
