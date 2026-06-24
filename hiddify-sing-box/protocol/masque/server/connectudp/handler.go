package connectudp

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/dunglas/httpsfv"
	"github.com/quic-go/quic-go/http3"
	cudpframe "github.com/sagernet/sing-box/transport/masque/connectudp/frame"
	cudph2 "github.com/sagernet/sing-box/transport/masque/connectudp/h2"
	cudprelay "github.com/sagernet/sing-box/transport/masque/connectudp/relay"
)

// tuneH2OnwardUDP sets kernel snd/rcv buffers on server CONNECT-UDP onward UDP (relay H3 parity).
func tuneH2OnwardUDP(conn *net.UDPConn) {
	cudprelay.TuneMasqueUDPSocketBuffers(conn)
}

func closeH2OnwardConn(conn *net.UDPConn) {
	if conn != nil {
		_ = conn.Close()
	}
}

const RequestProtocol = cudpframe.RequestProtocol

// TargetPolicy mirrors CONNECT-stream / CONNECT-IP onward ACL for CONNECT-UDP (H2+H3).
type TargetPolicy struct {
	AllowPrivateTargets bool
	AllowedTargetPorts  []uint16
	BlockedTargetPorts  []uint16
}

// Hooks wires server-side ACL and header helpers from protocol/masque/server.
type Hooks struct {
	ResolveTCPTarget             func(ctx context.Context, host string, allowPrivate bool) (string, error)
	AllowTCPPort                 func(portStr string, allowed, blocked []uint16) bool
	CapsuleProtocolHeaderValue   func() string
	ExtendedMasqueTunnelProtocol func(r *http.Request) string
}

// Handler serves CONNECT-UDP over HTTP/3 (relay) or HTTP/2 (capsule relay).
type Handler struct {
	Hooks Hooks
	// H2SessionRegistry scopes asymmetric H2 CONNECT-UDP sessions (nil → package default).
	H2SessionRegistry *cudph2.SessionRegistry
}

func (h Handler) h2Sessions() *cudph2.SessionRegistry {
	if h.H2SessionRegistry != nil {
		return h.H2SessionRegistry
	}
	return cudph2.DefaultSessionRegistry
}

var errTargetPortDenied = errors.New("connect-udp: port policy denied")

func (h Handler) checkTargetPolicy(ctx context.Context, target string, policy TargetPolicy) error {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}
	if h.Hooks.ResolveTCPTarget != nil {
		if _, allowErr := h.Hooks.ResolveTCPTarget(ctx, host, policy.AllowPrivateTargets); allowErr != nil {
			return allowErr
		}
	}
	if h.Hooks.AllowTCPPort != nil && !h.Hooks.AllowTCPPort(portStr, policy.AllowedTargetPorts, policy.BlockedTargetPorts) {
		return errTargetPortDenied
	}
	return nil
}

func targetPolicyHTTPStatus(err error) int {
	if err == nil {
		return http.StatusOK
	}
	if errors.Is(err, errTargetPortDenied) {
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

// ResolveDialToHTTPStatus maps UDP resolve/dial failures to HTTP status codes.
func ResolveDialToHTTPStatus(err error) int {
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

// HandleConnectUDP serves RFC 9298 CONNECT-UDP over HTTP/3 or HTTP/2.
func (h Handler) HandleConnectUDP(w http.ResponseWriter, r *http.Request, parsed *cudpframe.Request, udpProxy *cudprelay.Proxy, policy TargetPolicy) {
	if polErr := h.checkTargetPolicy(r.Context(), parsed.Target, policy); polErr != nil {
		w.WriteHeader(targetPolicyHTTPStatus(polErr))
		return
	}
	if _, ok := w.(http3.HTTPStreamer); ok {
		if err := udpProxy.Proxy(w, parsed); err != nil {
			w.WriteHeader(http.StatusBadGateway)
		}
		return
	}
	protoFn := h.Hooks.ExtendedMasqueTunnelProtocol
	if protoFn == nil {
		protoFn = defaultExtendedMasqueTunnelProtocol
	}
	if !strings.EqualFold(protoFn(r), RequestProtocol) {
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
		w.WriteHeader(ResolveDialToHTTPStatus(err))
		return
	}
	proxyStatus.Params.Add("next-hop", addr.String())

	role := cudph2.StreamRoleFromRequest(r)
	if role != "" {
		sessKey, keyErr := cudph2.RequireSessionKey(r, addr.String())
		if keyErr != nil {
			if cudph2.IsMissingMuxKey(keyErr) {
				_ = writeProxyStatus(keyErr)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_ = writeProxyStatus(keyErr)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if role == cudph2.StreamRoleDownload && h.h2Sessions().HasActiveDownload(sessKey) {
			_ = writeProxyStatus(cudph2.ErrDuplicateDownloadSession)
			w.WriteHeader(http.StatusConflict)
			return
		}
	}

	var conn *net.UDPConn
	if role != cudph2.StreamRoleUpload {
		var dialErr error
		conn, dialErr = net.DialUDP("udp", nil, addr)
		if dialErr != nil {
			proxyStatus.Params.Add("error", "destination_ip_unroutable")
			_ = writeProxyStatus(dialErr)
			w.WriteHeader(ResolveDialToHTTPStatus(dialErr))
			return
		}
		tuneH2OnwardUDP(conn)
	}

	if err := writeProxyStatus(nil); err != nil {
		closeH2OnwardConn(conn)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	_ = http.NewResponseController(w).EnableFullDuplex()
	capsuleVal := ""
	if h.Hooks.CapsuleProtocolHeaderValue != nil {
		capsuleVal = h.Hooks.CapsuleProtocolHeaderValue()
	}
	w.Header().Set(http3.CapsuleProtocolHeader, capsuleVal)
	w.WriteHeader(http.StatusOK)
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
	if err := cudph2.ServeH2FromRequest(w, r, conn, addr.String(), h.h2Sessions()); err != nil {
		if cudph2.IsDuplicateDownloadSession(err) {
			return
		}
	}
}

func defaultExtendedMasqueTunnelProtocol(r *http.Request) string {
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
