package server

import (
	"net/http"
	"strings"

	TM "github.com/sagernet/sing-box/transport/masque"
	cudpframe "github.com/sagernet/sing-box/transport/masque/connectudp/frame"
	cudpsrv "github.com/sagernet/sing-box/protocol/masque/server/connectudp"
	cudprelay "github.com/sagernet/sing-box/transport/masque/connectudp/relay"
)

const masqueRequestProtocolConnectUDP = cudpsrv.RequestProtocol

// ConnectUDPTargetPolicy mirrors CONNECT-stream / CONNECT-IP onward ACL for CONNECT-UDP (H2+H3).
type ConnectUDPTargetPolicy = cudpsrv.TargetPolicy

// ExtendedMasqueTunnelProtocol returns the CONNECT tunnel pseudo-protocol
// (:protocol header on H2 or Proto on H3).
func ExtendedMasqueTunnelProtocol(r *http.Request) string {
	if r == nil {
		return ""
	}
	if v := strings.TrimSpace(r.Header.Get(":protocol")); v != "" {
		return v
	}
	p := strings.TrimSpace(r.Proto)
	if p == "" {
		return ""
	}
	if len(p) >= 5 && strings.EqualFold(p[:5], "http/") {
		return ""
	}
	return p
}

var connectUDPHandler = cudpsrv.Handler{
	Hooks: cudpsrv.Hooks{
		ResolveTCPTarget:             ResolveTCPTargetForDial,
		AllowTCPPort:                 AllowTCPPort,
		CapsuleProtocolHeaderValue:   TM.CapsuleProtocolHeaderValueH2,
		ExtendedMasqueTunnelProtocol: ExtendedMasqueTunnelProtocol,
	},
}

// ConnectUDPResolveDialToHTTPStatus maps UDP resolve/dial failures to HTTP status codes.
func ConnectUDPResolveDialToHTTPStatus(err error) int {
	return cudpsrv.ResolveDialToHTTPStatus(err)
}

// HandleConnectUDP serves RFC 9298 CONNECT-UDP over HTTP/3 (connectudp/relay) or HTTP/2 capsule relay.
func HandleConnectUDP(w http.ResponseWriter, r *http.Request, parsed *cudpframe.Request, udpProxy *cudprelay.Proxy, policy ConnectUDPTargetPolicy) {
	connectUDPHandler.HandleConnectUDP(w, r, parsed, udpProxy, policy)
}
