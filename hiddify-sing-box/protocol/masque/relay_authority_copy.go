package masque

import (
	"context"
	"io"
	"net"
	"net/http"
)

// relayAuthorityIOCopy is tcp_relay authority (CONNECT https://dest/). Uses relayTCPForward (h2o tunnel by default).
func relayAuthorityIOCopy(ctx context.Context, targetConn net.Conn, reqBody io.ReadCloser, responseWriter http.ResponseWriter) error {
	return relayTCPForward(ctx, targetConn, reqBody, responseWriter)
}
