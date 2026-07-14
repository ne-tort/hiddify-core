package relay

import (
	"context"
	"io"
	"net"
	"net/http"

	strm "github.com/sagernet/sing-box/transport/masque/stream"
)

// TCPForward relays CONNECT tunneled TCP via transport/masque stream (h2o-style bidi only).
func TCPForward(ctx context.Context, targetConn net.Conn, reqBody io.ReadCloser, responseWriter http.ResponseWriter) error {
	return strm.RelayTCPTunnel(ctx, targetConn, reqBody, responseWriter)
}
