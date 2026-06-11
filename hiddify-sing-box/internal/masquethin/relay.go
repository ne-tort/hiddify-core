package masquethin

import (
	"context"
	"io"
	"net"
	"net/http"

	TM "github.com/sagernet/sing-box/transport/masque"
)

// RelayUploadFromStream reads client upload from the hijacked HTTP/3 stream instead of req.Body.
func RelayUploadFromStream() bool {
	return TM.RelayUploadFromStream()
}

// RelayTCPTunnel relays CONNECT tunneled TCP like h2o proxy.tunnel (64 KiB io.CopyBuffer, full duplex).
func RelayTCPTunnel(ctx context.Context, targetConn net.Conn, reqBody io.ReadCloser, responseWriter http.ResponseWriter) error {
	return TM.RelayTCPTunnel(ctx, targetConn, reqBody, responseWriter)
}
