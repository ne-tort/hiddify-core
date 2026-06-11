package masque

import (
	"net"

	"github.com/quic-go/quic-go"
)

// RelayTuneOutboundTCPConn matches masque-thin-server onward TCP tuning (NoDelay only).
func RelayTuneOutboundTCPConn(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
}

// MasqueAuthorityHTTPServerQUICConfig is QUIC tuning for authority-only HTTP/3 listeners (no datagram plane).
func MasqueAuthorityHTTPServerQUICConfig() *quic.Config {
	cfg := MasqueHTTPServerQUICConfig()
	if cfg != nil {
		cfg.EnableDatagrams = false
	}
	return cfg
}
