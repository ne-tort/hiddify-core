package h2

import (
	"context"
	"io"
	"net"
	"net/http"
	"strconv"

	strm "github.com/sagernet/sing-box/transport/masque/stream"
)

// ConnectTunnelFromResponse builds a thin RFC 8441 tunnel after Extended CONNECT succeeds.
// uploadBody is the request-body reader wired into http2.Transport (wire-barrier tracking).
func ConnectTunnelFromResponse(streamCtx context.Context, resp *http.Response, upload io.WriteCloser, uploadBody io.Reader, targetHost string, targetPort uint16) (net.Conn, error) {
	if resp == nil || resp.Body == nil || upload == nil {
		return nil, strm.Errs.TCPConnectStreamFailed
	}
	remoteAddr, _ := net.ResolveTCPAddr("tcp", net.JoinHostPort(targetHost, strconv.Itoa(int(targetPort))))
	paths := NewTunnelPaths(resp.Body, upload)
	inner := strm.ConnFromTunnelPaths(streamCtx, paths, &net.TCPAddr{}, remoteAddr)
	var barrier strm.UploadWireBarrier
	if b, ok := uploadBody.(*ExtendedConnectUploadBody); ok {
		barrier = b
	}
	if err := strm.PrimeH2UploadBootstrapOnConn(inner, barrier); err != nil {
		_ = inner.Close()
		return nil, err
	}
	// CONNECT-stream does not call BeginUploadWriterLive — MarkUploadWriterDone would be a no-op.
	// UDP/IP asymmetric legs wire teardown themselves after BeginUploadWriterLive.
	return strm.NewTunnelConn(inner), nil
}
