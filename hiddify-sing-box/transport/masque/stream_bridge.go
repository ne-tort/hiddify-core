package masque

import (
	"context"
	"io"
	"net"
	"net/http"

	strm "github.com/sagernet/sing-box/transport/masque/stream"
)

func init() {
	strm.SetErrors(strm.Errors{
		TCPConnectStreamFailed: ErrTCPConnectStreamFailed,
		Capability:             ErrCapability,
	})
}

// RelayTunnelBufLen matches h2o proxy.max-buffer-size on MASQUE CONNECT tunnels.
const RelayTunnelBufLen = strm.RelayTunnelBufLen

func RelayUseHTTP3StreamHijack() bool { return strm.RelayUseHTTP3StreamHijack() }

func RelayUploadFromStream() bool { return strm.RelayUploadFromStream() }

// RelayTCPTunnel relays CONNECT tunneled TCP (shared client+server implementation in stream/).
func RelayTCPTunnel(ctx context.Context, targetConn net.Conn, reqBody io.ReadCloser, responseWriter http.ResponseWriter) error {
	return strm.RelayTCPTunnel(ctx, targetConn, reqBody, responseWriter)
}
