package server

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/dunglas/httpsfv"
	qmasque "github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go/http3"
	TM "github.com/sagernet/sing-box/transport/masque"
	cudp "github.com/sagernet/sing-box/transport/masque/connectudp"
)

const masqueRequestProtocolConnectUDP = "connect-udp"

// ConnectUDPTargetPolicy mirrors CONNECT-stream / CONNECT-IP onward ACL for CONNECT-UDP (H2+H3).
type ConnectUDPTargetPolicy struct {
	AllowPrivateTargets bool
	AllowedTargetPorts  []uint16
	BlockedTargetPorts  []uint16
}

var errConnectUDPTargetPortDenied = errors.New("connect-udp: port policy denied")

func checkConnectUDPTargetPolicy(ctx context.Context, target string, policy ConnectUDPTargetPolicy) error {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}
	if _, allowErr := ResolveTCPTargetForDial(ctx, host, policy.AllowPrivateTargets); allowErr != nil {
		return allowErr
	}
	if !AllowTCPPort(portStr, policy.AllowedTargetPorts, policy.BlockedTargetPorts) {
		return errConnectUDPTargetPortDenied
	}
	return nil
}

func connectUDPTargetPolicyHTTPStatus(err error) int {
	if err == nil {
		return http.StatusOK
	}
	if errors.Is(err, errConnectUDPTargetPortDenied) {
		return http.StatusForbidden
	}
	if strings.Contains(err.Error(), "private target denied") {
		return http.StatusForbidden
	}
	var addrErr *net.AddrError
	var parseErr *net.ParseError
	if errors.As(err, &addrErr) || errors.As(err, &parseErr) {
		return http.StatusBadRequest
	}
	return http.StatusBadRequest
}

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

// ConnectUDPResolveDialToHTTPStatus maps UDP resolve/dial failures to HTTP status codes.
func ConnectUDPResolveDialToHTTPStatus(err error) int {
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

// HandleConnectUDP serves RFC 9298 CONNECT-UDP over HTTP/3 (masque-go proxy) or HTTP/2 capsule relay.
func HandleConnectUDP(w http.ResponseWriter, r *http.Request, parsed *qmasque.Request, udpProxy *qmasque.Proxy, policy ConnectUDPTargetPolicy) {
	if polErr := checkConnectUDPTargetPolicy(r.Context(), parsed.Target, policy); polErr != nil {
		w.WriteHeader(connectUDPTargetPolicyHTTPStatus(polErr))
		return
	}
	if _, ok := w.(http3.HTTPStreamer); ok {
		if err := udpProxy.Proxy(w, parsed); err != nil {
			w.WriteHeader(http.StatusBadGateway)
		}
		return
	}
	if !strings.EqualFold(ExtendedMasqueTunnelProtocol(r), masqueRequestProtocolConnectUDP) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	proxyStatus := httpsfv.NewItem(parsed.Host)
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

	addr, err := net.ResolveUDPAddr("udp", parsed.Target)
	if err != nil {
		var dnsError *net.DNSError
		if errors.As(err, &dnsError) {
			dnsErrorToMasqueProxyStatus(&proxyStatus, dnsError)
		}
		_ = writeProxyStatus(err)
		w.WriteHeader(ConnectUDPResolveDialToHTTPStatus(err))
		return
	}
	proxyStatus.Params.Add("next-hop", addr.String())

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		proxyStatus.Params.Add("error", "destination_ip_unroutable")
		_ = writeProxyStatus(err)
		w.WriteHeader(ConnectUDPResolveDialToHTTPStatus(err))
		return
	}

	if err := writeProxyStatus(nil); err != nil {
		_ = conn.Close()
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// RFC 8441 CONNECT-UDP: relay reads request DATAGRAM capsules while writing the response body.
	_ = http.NewResponseController(w).EnableFullDuplex()
	w.Header().Set(http3.CapsuleProtocolHeader, TM.CapsuleProtocolHeaderValueH2())
	w.WriteHeader(http.StatusOK)
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
	_ = cudp.ServeH2(w, r, conn)
}
