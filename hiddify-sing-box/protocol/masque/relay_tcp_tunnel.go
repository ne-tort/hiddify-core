package masque

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"strings"

	TM "github.com/sagernet/sing-box/transport/masque"
)

// masqueRelayUseLegacyFlushRelay selects the old template relay (per-read flush, prime chunk).
// Default is h2o/Invisv-style full-duplex io.Copy tunnel (MASQUE_RELAY_TCP_LEGACY=1 to revert).
func masqueRelayUseLegacyFlushRelay() bool {
	return strings.TrimSpace(os.Getenv("MASQUE_RELAY_TCP_LEGACY")) == "1"
}

// relayTCPForward is the server TCP relay entry: tunnel (default) or legacy flush relay.
func relayTCPForward(ctx context.Context, targetConn net.Conn, reqBody io.ReadCloser, responseWriter http.ResponseWriter) error {
	if masqueRelayUseLegacyFlushRelay() {
		return relayTCPBidirectional(ctx, targetConn, reqBody, responseWriter)
	}
	return relayTCPTunnel(ctx, targetConn, reqBody, responseWriter)
}

func relayTCPTunnel(ctx context.Context, targetConn net.Conn, reqBody io.ReadCloser, responseWriter http.ResponseWriter) error {
	return TM.RelayTCPTunnel(ctx, targetConn, reqBody, responseWriter)
}
