package relay

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"strings"

	TM "github.com/sagernet/sing-box/transport/masque"
)

// UseLegacyFlushRelay selects the old template relay (per-read flush, prime chunk).
// Default is h2o/Invisv-style full-duplex io.Copy tunnel (MASQUE_RELAY_TCP_LEGACY=1 to revert).
func UseLegacyFlushRelay() bool {
	return strings.TrimSpace(os.Getenv("MASQUE_RELAY_TCP_LEGACY")) == "1"
}

// TCPForward is the server TCP relay entry: tunnel (default) or legacy flush relay.
func TCPForward(ctx context.Context, targetConn net.Conn, reqBody io.ReadCloser, responseWriter http.ResponseWriter) error {
	if UseLegacyFlushRelay() {
		return TCPBidirectional(ctx, targetConn, reqBody, responseWriter)
	}
	return TCPTunnel(ctx, targetConn, reqBody, responseWriter)
}

// TCPTunnel relays CONNECT tunneled TCP via transport/masque stream (h2o-style).
func TCPTunnel(ctx context.Context, targetConn net.Conn, reqBody io.ReadCloser, responseWriter http.ResponseWriter) error {
	return TM.RelayTCPTunnel(ctx, targetConn, reqBody, responseWriter)
}
