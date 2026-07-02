package h2

import (
	"errors"
	"net"
	"net/http"

	"github.com/quic-go/quic-go/http3"
	connectudp "github.com/sagernet/sing-box/transport/masque/connectudp"
	cudpframe "github.com/sagernet/sing-box/transport/masque/connectudp/frame"
	cudprelay "github.com/sagernet/sing-box/transport/masque/connectudp/relay"
)

// ServeConnectUDPConfig wires HTTP/2 CONNECT-UDP server entry from protocol/masque/server/connectudp.
type ServeConnectUDPConfig struct {
	CapsuleProtocolHeaderValue func() string
	Sessions                   *SessionRegistry
}

func (cfg ServeConnectUDPConfig) sessions() *SessionRegistry {
	if cfg.Sessions != nil {
		return cfg.Sessions
	}
	return DefaultSessionRegistry
}

func tuneH2OnwardUDP(conn *net.UDPConn) {
	cudprelay.TuneMasqueUDPSocketBuffers(conn)
}

func closeH2OnwardConn(conn *net.UDPConn) {
	if conn != nil {
		_ = conn.Close()
	}
}

// ServeConnectUDP handles the HTTP/2 CONNECT-UDP server leg (capsule relay) after ACL checks.
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

	role := StreamRoleFromRequest(r)
	if role != "" {
		_, keyErr := RequireSessionKey(r, addr.String())
		if keyErr != nil {
			if IsMissingMuxKey(keyErr) {
				_ = cudpframe.WriteProxyStatusHeader(w, &proxyStatus, keyErr)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_ = cudpframe.WriteProxyStatusHeader(w, &proxyStatus, keyErr)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	}

	var conn *net.UDPConn
	if role != StreamRoleUpload {
		var dialErr error
		conn, dialErr = net.DialUDP("udp", nil, addr)
		if dialErr != nil {
			proxyStatus.Params.Add("error", "destination_ip_unroutable")
			_ = cudpframe.WriteProxyStatusHeader(w, &proxyStatus, dialErr)
			w.WriteHeader(connectudp.ResolveDialToHTTPStatus(dialErr))
			return
		}
		tuneH2OnwardUDP(conn)
	}

	sessions := cfg.sessions()
	if role == StreamRoleDownload {
		if regErr := RegisterDownloadBeforeOK(w, r, conn, addr.String(), sessions); regErr != nil {
			closeH2OnwardConn(conn)
			_ = cudpframe.WriteProxyStatusHeader(w, &proxyStatus, regErr)
			if IsDuplicateDownloadSession(regErr) {
				w.WriteHeader(http.StatusConflict)
			} else if IsMissingMuxKey(regErr) {
				w.WriteHeader(http.StatusBadRequest)
			} else {
				w.WriteHeader(http.StatusInternalServerError)
			}
			return
		}
	}
	if role == StreamRoleUpload {
		if waitErr := WaitDownloadSessionBeforeOK(r, addr.String(), sessions); waitErr != nil {
			_ = cudpframe.WriteProxyStatusHeader(w, &proxyStatus, waitErr)
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
	}

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
	if role == StreamRoleUpload {
		w.WriteHeader(http.StatusOK)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		if err := ServeH2FromRequest(w, r, conn, addr.String(), sessions); err != nil {
			if IsDuplicateDownloadSession(err) {
				return
			}
		}
		return
	}
	w.WriteHeader(http.StatusOK)
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
	if err := ServeH2FromRequest(w, r, conn, addr.String(), sessions); err != nil {
		if IsDuplicateDownloadSession(err) {
			return
		}
	}
}
