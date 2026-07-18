package h2

import (
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/dunglas/httpsfv"
	"github.com/quic-go/quic-go/http3"
	connectudp "github.com/sagernet/sing-box/transport/masque/connectudp"
	cudpframe "github.com/sagernet/sing-box/transport/masque/connectudp/frame"
	cudprelay "github.com/sagernet/sing-box/transport/masque/connectudp/relay"
)

// Proprietary dual-leg headers (CUT on this branch). Reject if present so no silent asym path remains.
const (
	legacyMasqueUDPStreamRoleHeader = "Masque-Udp-Stream-Role"
	legacyMasqueUDPMuxKeyHeader     = "Masque-Udp-Mux-Key"
)

// ServeConnectUDPConfig wires HTTP/2 CONNECT-UDP server entry from protocol/masque/server/connectudp.
type ServeConnectUDPConfig struct {
	CapsuleProtocolHeaderValue func() string
}

func tuneH2OnwardUDP(conn *net.UDPConn) {
	cudprelay.TuneMasqueUDPSocketBuffers(conn)
}

func closeH2OnwardConn(conn *net.UDPConn) {
	if conn != nil {
		_ = conn.Close()
	}
}

func rejectLegacyAsymHeaders(w http.ResponseWriter, r *http.Request, proxyStatus *httpsfv.Item) bool {
	if r == nil {
		return false
	}
	if strings.TrimSpace(r.Header.Get(legacyMasqueUDPStreamRoleHeader)) == "" &&
		strings.TrimSpace(r.Header.Get(legacyMasqueUDPMuxKeyHeader)) == "" {
		return false
	}
	_ = cudpframe.WriteProxyStatusHeader(w, proxyStatus, errors.New("masque h2: asymmetric CONNECT-UDP headers not supported"))
	w.WriteHeader(http.StatusBadRequest)
	return true
}

// ServeConnectUDP handles the HTTP/2 CONNECT-UDP server (RFC single-stream capsule relay).
func ServeConnectUDP(w http.ResponseWriter, r *http.Request, target, authorityHost string, cfg ServeConnectUDPConfig) {
	proxyStatus := cudpframe.NewProxyStatusItem(authorityHost)

	addr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		var dnsError *net.DNSError
		if errors.As(err, &dnsError) {
			cudpframe.DNSErrorToProxyStatus(&proxyStatus, dnsError)
		}
		_ = cudpframe.WriteProxyStatusHeader(w, &proxyStatus, err)
		w.WriteHeader(connectudp.ResolveDialToHTTPStatus(err))
		return
	}
	proxyStatus.Params.Add("next-hop", addr.String())

	if rejectLegacyAsymHeaders(w, r, &proxyStatus) {
		return
	}

	conn, dialErr := net.DialUDP("udp", nil, addr)
	if dialErr != nil {
		proxyStatus.Params.Add("error", "destination_ip_unroutable")
		_ = cudpframe.WriteProxyStatusHeader(w, &proxyStatus, dialErr)
		w.WriteHeader(connectudp.ResolveDialToHTTPStatus(dialErr))
		return
	}
	tuneH2OnwardUDP(conn)

	if err := cudpframe.WriteProxyStatusHeader(w, &proxyStatus, nil); err != nil {
		closeH2OnwardConn(conn)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	_ = http.NewResponseController(w).EnableFullDuplex()
	capsuleVal := cudpframe.CapsuleProtocolHeaderValue
	if cfg.CapsuleProtocolHeaderValue != nil {
		capsuleVal = cfg.CapsuleProtocolHeaderValue()
	}
	w.Header().Set(http3.CapsuleProtocolHeader, capsuleVal)
	w.WriteHeader(http.StatusOK)
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
	_ = ServeH2(w, r, conn)
}
