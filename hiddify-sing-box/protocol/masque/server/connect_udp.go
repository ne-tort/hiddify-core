package server

import (
	"net/http"

	cudp "github.com/sagernet/sing-box/protocol/masque/server/connectudp"
	cudpframe "github.com/sagernet/sing-box/transport/masque/connectudp/frame"
	cudprelay "github.com/sagernet/sing-box/transport/masque/connectudp/relay"
	h2c "github.com/sagernet/sing-box/transport/masque/h2"
)

// ConnectUDPTargetPolicy mirrors endpoint onward ACL knobs for CONNECT-UDP (H2+H3).
type ConnectUDPTargetPolicy = cudp.TargetPolicy

var defaultConnectUDPHandler = cudp.Handler{
	Hooks: cudp.Hooks{
		ResolveTCPTarget:           ResolveTCPTargetForDial,
		AllowTCPPort:               AllowTCPPort,
		CapsuleProtocolHeaderValue: h2c.CapsuleProtocolHeaderValue,
	},
}

// HandleConnectUDP serves RFC 9297/9298 CONNECT-UDP over HTTP/3 (relay) or HTTP/2 (capsules).
func HandleConnectUDP(w http.ResponseWriter, r *http.Request, parsed *cudpframe.Request, udpProxy *cudprelay.Proxy, policy ConnectUDPTargetPolicy) {
	defaultConnectUDPHandler.HandleConnectUDP(w, r, parsed, udpProxy, policy)
}

// ExtendedMasqueTunnelProtocol reads :protocol (H2) or Proto (H3 compat) from a CONNECT request.
func ExtendedMasqueTunnelProtocol(r *http.Request) string {
	return cudp.DefaultExtendedMasqueTunnelProtocol(r)
}

// ConnectUDPResolveDialToHTTPStatus maps UDP resolve/dial failures to HTTP status codes.
func ConnectUDPResolveDialToHTTPStatus(err error) int {
	return cudp.ResolveDialToHTTPStatus(err)
}
