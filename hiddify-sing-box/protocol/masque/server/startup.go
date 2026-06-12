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

// AuthorityStartupFlags reports authority-only H3 listen and minimal mux for Start().
func AuthorityStartupFlags(tcpRelay string, options option.MasqueEndpointOptions) (authorityH3Only bool, authorityMinimal bool) {
	authorityH3Only = tcpRelay == option.MasqueTCPRelayAuthority
	authorityMinimal = authorityH3Only && AuthorityServerMinimalForOptions(options)
	return authorityH3Only, authorityMinimal
}

// BuildStartupHandler selects the HTTP handler before dual-bind listen (full mux vs authority minimal).
func BuildStartupHandler(host MuxHost, tcpRelay string, options option.MasqueEndpointOptions) (http.Handler, error) {
	_, authorityMinimal := AuthorityStartupFlags(tcpRelay, options)
	if authorityMinimal {
		return NewAuthorityMinimalHandler(TCPConnectAuthorityHost{
			Options:   options,
			Dialer:    host.Dialer,
			Authorize: host.Authorize,
		}), nil
	}
	return BuildMuxHandler(host, tcpRelay)
}
