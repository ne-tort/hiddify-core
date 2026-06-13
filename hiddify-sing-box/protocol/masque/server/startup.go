package server

import (
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/option"
)

// MasqueListenAddr returns host:port for server bind (empty host → 0.0.0.0).
func MasqueListenAddr(listenHost string, listenPort uint16) string {
	host := strings.TrimSpace(listenHost)
	if host == "" {
		host = "0.0.0.0"
	}
	return net.JoinHostPort(host, strconv.Itoa(int(listenPort)))
}

// BuildStartupHandler builds the template TCP relay HTTP mux for server listen.
func BuildStartupHandler(host MuxHost, tcpRelay string, _ option.MasqueEndpointOptions) (http.Handler, error) {
	return BuildMuxHandler(host, tcpRelay)
}
