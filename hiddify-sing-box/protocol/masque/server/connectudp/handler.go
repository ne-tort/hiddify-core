package connectudp

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/quic-go/quic-go/http3"
	cudpframe "github.com/sagernet/sing-box/transport/masque/connectudp/frame"
	cudph2 "github.com/sagernet/sing-box/transport/masque/connectudp/h2"
	cudpasym "github.com/sagernet/sing-box/transport/masque/connectudp/asym"
	cudprelay "github.com/sagernet/sing-box/transport/masque/connectudp/relay"
	connectudp "github.com/sagernet/sing-box/transport/masque/connectudp"
)

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
	// H3SessionRegistry scopes asymmetric H3 CONNECT-UDP sessions (nil → relay default).
	H3SessionRegistry *cudprelay.H3SessionRegistry
}

func (h Handler) h3Sessions() *cudprelay.H3SessionRegistry {
	if h.H3SessionRegistry != nil {
		return h.H3SessionRegistry
	}
	return cudprelay.DefaultH3SessionRegistry
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
	if errors.Is(err, errTargetPortDenied) || errors.Is(err, connectudp.ErrPrivateTargetDenied) {
		return http.StatusForbidden
	}
	var addrErr *net.AddrError
	var parseErr *net.ParseError
	if errors.As(err, &addrErr) || errors.As(err, &parseErr) {
		return http.StatusBadRequest
	}
	return http.StatusBadRequest
}

// ResolveDialToHTTPStatus maps UDP resolve/dial failures to HTTP status codes.
func ResolveDialToHTTPStatus(err error) int {
	return connectudp.ResolveDialToHTTPStatus(err)
}

// HandleConnectUDP serves RFC 9298 CONNECT-UDP over HTTP/3 or HTTP/2.
func (h Handler) HandleConnectUDP(w http.ResponseWriter, r *http.Request, parsed *cudpframe.Request, udpProxy *cudprelay.Proxy, policy TargetPolicy) {
	if h.Hooks.ResolveTCPTarget == nil || h.Hooks.AllowTCPPort == nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if polErr := h.checkTargetPolicy(r.Context(), parsed.Target, policy); polErr != nil {
		w.WriteHeader(targetPolicyHTTPStatus(polErr))
		return
	}
	if _, ok := w.(http3.HTTPStreamer); ok {
		if cudpasym.StreamRoleFromRequest(r) != "" {
			if err := cudprelay.ServeH3Asymmetric(w, r, parsed, h.h3Sessions()); err != nil {
				if cudpasym.IsMissingMuxKey(err) {
					w.WriteHeader(http.StatusBadRequest)
				} else if errors.Is(err, cudprelay.ErrDuplicateH3DownloadSession) {
					w.WriteHeader(http.StatusConflict)
				}
				return
			}
			return
		}
		if err := udpProxy.ProxyWithContext(r.Context(), w, parsed); err != nil {
			return
		}
		return
	}
	protoFn := h.Hooks.ExtendedMasqueTunnelProtocol
	if protoFn == nil {
		protoFn = DefaultExtendedMasqueTunnelProtocol
	}
	if !strings.EqualFold(protoFn(r), RequestProtocol) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	cudph2.ServeConnectUDP(w, r, parsed.Target, parsed.Host, cudph2.ServeConnectUDPConfig{
		CapsuleProtocolHeaderValue: h.Hooks.CapsuleProtocolHeaderValue,
		Sessions:                   h.h2Sessions(),
	})
}

// DefaultExtendedMasqueTunnelProtocol reads :protocol (H2) or Proto (H3 compat) from a CONNECT request.
func DefaultExtendedMasqueTunnelProtocol(r *http.Request) string {
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
