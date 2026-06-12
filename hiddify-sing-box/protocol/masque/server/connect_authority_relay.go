package server

import (
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/protocol/masque/relay"
)

// CONNECTAuthorityPolicy controls CONNECT-by-authority relay on the server.
type CONNECTAuthorityPolicy struct {
	AllowPrivateTargets bool
	AllowedPorts        []uint16
	BlockedPorts        []uint16
	Authorize           func(*http.Request) bool
	ResolveHost         func(ctx context.Context, host string) (string, error)
}

// ServeCONNECTAuthority handles RFC 9114 CONNECT https://host:port/ and relays onward TCP.
// Relay uses RelayTCPTunnel (64 KiB io.CopyBuffer, HTTP/3 stream hijack when available).
func ServeCONNECTAuthority(
	w http.ResponseWriter,
	r *http.Request,
	policy CONNECTAuthorityPolicy,
	dial func(ctx context.Context, network, addr string) (net.Conn, error),
) {
	if r.Method != http.MethodConnect {
		http.NotFound(w, r)
		return
	}
	if policy.Authorize != nil && !policy.Authorize(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if p := strings.TrimSpace(r.Header.Get(":protocol")); p != "" && !strings.EqualFold(p, "HTTP/2") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	targetHost, targetPort, parseErr := ParseCONNECTAuthorityTarget(r)
	if parseErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	resolvedHost := strings.Trim(strings.TrimSpace(targetHost), "[]")
	if policy.ResolveHost != nil {
		var resolveErr error
		resolvedHost, resolveErr = policy.ResolveHost(r.Context(), targetHost)
		if resolveErr != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}
	} else if !policy.AllowPrivateTargets && !allowAuthorityOnwardHost(targetHost) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if !allowAuthorityTCPPort(targetPort, policy.AllowedPorts, policy.BlockedPorts) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	portNum, portErr := strconv.ParseUint(targetPort, 10, 16)
	if portErr != nil || portNum == 0 || portNum > 65535 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	dialAddr := OnwardTCPDialAddr(resolvedHost, uint16(portNum))
	targetConn, dialErr := dial(r.Context(), "tcp", dialAddr)
	if dialErr != nil {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	defer targetConn.Close()
	relay.TuneTCPOutbound(targetConn)
	_ = http.NewResponseController(w).EnableFullDuplex()
	w.WriteHeader(http.StatusOK)
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
	relayErr := relay.TCPTunnel(r.Context(), targetConn, r.Body, w)
	if relayErr != nil && relayErr != io.EOF {
		return
	}
}

func allowAuthorityOnwardHost(host string) bool {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" || strings.EqualFold(host, "localhost") {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return true
	}
	return !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsMulticast() && !ip.IsUnspecified()
}

func allowAuthorityTCPPort(portRaw string, allowList, denyList []uint16) bool {
	port, err := strconv.Atoi(strings.TrimSpace(portRaw))
	if err != nil || port <= 0 || port > 65535 {
		return false
	}
	for _, denied := range denyList {
		if int(denied) == port {
			return false
		}
	}
	if len(allowList) == 0 {
		return true
	}
	for _, allowed := range allowList {
		if int(allowed) == port {
			return true
		}
	}
	return false
}
