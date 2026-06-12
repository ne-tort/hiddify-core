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
func ConnectTunnelFromResponse(streamCtx context.Context, resp *http.Response, upload *io.PipeWriter, targetHost string, targetPort uint16) (net.Conn, error) {
	if resp == nil || resp.Body == nil || upload == nil {
		return nil, strm.Errs.TCPConnectStreamFailed
	}
	remoteAddr, _ := net.ResolveTCPAddr("tcp", net.JoinHostPort(targetHost, strconv.Itoa(int(targetPort))))
	paths := NewTunnelPaths(resp.Body, upload)
	inner := strm.ConnFromTunnelPaths(streamCtx, paths, &net.TCPAddr{}, remoteAddr)
	return strm.NewTunnelConn(inner), nil
}
