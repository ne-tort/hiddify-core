package connectip

import (
	"net"
	"strconv"
	"strings"
)

// OverlayDialParams is the subset of client options used for CONNECT-IP overlay logs.
type OverlayDialParams struct {
	Server     string
	ServerPort int
	DialPeer   string
}

// OverlayDialAddr returns the TCP/TLS dial peer for CONNECT-IP overlay logs (H2/H3).
func OverlayDialAddr(p OverlayDialParams) string {
	portNum := p.ServerPort
	if portNum <= 0 {
		portNum = 443
	}
	host := strings.TrimSpace(p.DialPeer)
	if host == "" {
		host = strings.TrimSpace(p.Server)
	}
	return net.JoinHostPort(host, strconv.Itoa(portNum))
}
