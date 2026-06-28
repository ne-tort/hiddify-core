package h2

import (
	"errors"
	"net"
	"net/http"

	"github.com/dunglas/httpsfv"
	"github.com/quic-go/quic-go/http3"
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

func dnsErrorToMasqueProxyStatus(proxyStatus *httpsfv.Item, dnsError *net.DNSError) {
	if dnsError.Timeout() {
		proxyStatus.Params.Add("error", "dns_timeout")
		return
	}
	proxyStatus.Params.Add("error", "dns_error")
	if dnsError.IsNotFound {
		proxyStatus.Params.Add("rcode", "Negative response")
	} else {
		proxyStatus.Params.Add("rcode", "SERVFAIL")
	}
}

func resolveDialToHTTPStatus(err error) int {
	if err == nil {
		return http.StatusOK
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return http.StatusGatewayTimeout
	}
	var dnsError *net.DNSError
	if errors.As(err, &dnsError) {
		return http.StatusBadGateway
	}
	var addrErr *net.AddrError
	var parseError *net.ParseError
	if errors.As(err, &addrErr) || errors.As(err, &parseError) {
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

// ServeConnectUDP handles the HTTP/2 CONNECT-UDP server leg (capsule relay) after ACL checks.
func ServeConnectUDP(w http.ResponseWriter, r *http.Request, target, authorityHost string, cfg ServeConnectUDPConfig) {
	proxyStatus := httpsfv.NewItem(authorityHost)
	writeProxyStatus := func(err error) error {
		if err != nil {
			proxyStatus.Params.Add("details", err.Error())
		}
		val, marshalErr := httpsfv.Marshal(proxyStatus)
		if marshalErr != nil {
			return marshalErr
		}
		w.Header().Add("Proxy-Status", val)
		return err
	}

	addr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		var dnsError *net.DNSError
		if errors.As(err, &dnsError) {
			dnsErrorToMasqueProxyStatus(&proxyStatus, dnsError)
		}
		_ = writeProxyStatus(err)
		w.WriteHeader(resolveDialToHTTPStatus(err))
		return
	}
	proxyStatus.Params.Add("next-hop", addr.String())

	role := StreamRoleFromRequest(r)
	if role != "" {
		_, keyErr := RequireSessionKey(r, addr.String())
		if keyErr != nil {
			if IsMissingMuxKey(keyErr) {
				_ = writeProxyStatus(keyErr)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_ = writeProxyStatus(keyErr)
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
			_ = writeProxyStatus(dialErr)
			w.WriteHeader(resolveDialToHTTPStatus(dialErr))
			return
		}
		tuneH2OnwardUDP(conn)
	}

	sessions := cfg.sessions()
	if role == StreamRoleDownload {
		if regErr := RegisterDownloadBeforeOK(w, r, conn, addr.String(), sessions); regErr != nil {
			closeH2OnwardConn(conn)
			_ = writeProxyStatus(regErr)
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

	if err := writeProxyStatus(nil); err != nil {
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
	if err := ServeH2FromRequest(w, r, conn, addr.String(), sessions); err != nil {
		if IsDuplicateDownloadSession(err) {
			return
		}
	}
}
