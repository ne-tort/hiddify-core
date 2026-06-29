package relay

import (
	"context"
	"io"
	"net"
	"net/http"

	strm "github.com/sagernet/sing-box/transport/masque/stream"
)

// TCPForward relays CONNECT tunneled TCP via transport/masque stream (h2o-style).
func TCPForward(ctx context.Context, targetConn net.Conn, reqBody io.ReadCloser, responseWriter http.ResponseWriter, legRole string) error {
	return strm.RelayTCPTunnel(ctx, targetConn, reqBody, responseWriter, legRole)
}
