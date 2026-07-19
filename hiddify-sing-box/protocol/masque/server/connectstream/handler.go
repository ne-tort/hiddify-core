package connectstream

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/masque/relay"
	"github.com/sagernet/sing-box/transport/masque/pathbuild"
	"github.com/sagernet/sing-box/transport/masque/session"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/yosida95/uritemplate/v3"
)

// ConnectTCPProtocol is the required :protocol for Extended CONNECT TCP (draft-ietf-httpbis-connect-tcp).
const ConnectTCPProtocol = "connect-tcp"

// Hooks wires server-side ACL helpers from protocol/masque/server (onward_policy).
type Hooks struct {
	ResolveTCPTarget      func(ctx context.Context, host string, allowPrivate bool) (string, error)
	ResolveTCPTargetAddrs func(ctx context.Context, host string, allowPrivate bool) ([]netip.Addr, error)
	AllowTCPPort          func(portStr string, allowed, blocked []uint16) bool
	OnwardTCPDialAddr     func(host string, port uint16) string
	DialTCPTargetSerial   func(ctx context.Context, dialer net.Dialer, addrs []netip.Addr, port uint16) (net.Conn, netip.Addr, error)
	// ResolveErrorHTTPStatus maps onward resolve/policy errors to HTTP status (wired from server package).
	ResolveErrorHTTPStatus func(err error) int
}

// Host carries CONNECT-stream handler dependencies from the parent endpoint.
type Host struct {
	Options   option.MasqueEndpointOptions
	Logger    log.ContextLogger
	Dialer    net.Dialer
	Authorize func(*http.Request) bool
	// AuthorityMatches is retained for API compatibility; ParseTCPTarget no longer checks authority.
	AuthorityMatches func(templateHost, requestHost string, relax bool) bool
}

// Handler serves Extended CONNECT over the TCP path template.
type Handler struct {
	Hooks Hooks
}

// HandleConnectStream serves CONNECT-stream (RFC 8441 / connect-tcp) over the TCP MASQUE path.
func (h Handler) HandleConnectStream(host Host, w http.ResponseWriter, r *http.Request, tcpTemplate *uritemplate.Template, _ bool) {
	debugf := func(format string, args ...any) {
		if host.Logger == nil {
			return
		}
		host.Logger.DebugContext(r.Context(), fmt.Sprintf(format, args...))
	}
	if r.Method != http.MethodConnect {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	debugf("masque tcp connect request method=%s remote=%s uri=%s", r.Method, r.RemoteAddr, r.URL.String())
	if host.Authorize != nil && !host.Authorize(r) {
		debugf("masque tcp connect auth denied status=401")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	// draft-ietf-httpbis-connect-tcp: :protocol must be exactly "connect-tcp"
	// (H2: Header; H3/quic-go: Request.Proto).
	if p := extendedConnectProtocol(r); !strings.EqualFold(p, ConnectTCPProtocol) {
		debugf("masque tcp connect denied status=400 error_class=bad_extended_protocol proto=%q", p)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	targetHost, targetPort, parseErr := ParseTCPTargetFromRequest(r, tcpTemplate, host.Options.PathObfuscation)
	if parseErr != nil {
		debugf("masque tcp connect parse denied status=400 error_class=misconfig err=%v", parseErr)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	resolveAddrs := h.Hooks.ResolveTCPTargetAddrs
	if resolveAddrs == nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	resolvedAddrs, allowErr := resolveAddrs(r.Context(), targetHost, host.Options.AllowPrivateTargets)
	if allowErr != nil {
		status := http.StatusBadGateway
		if mapStatus := h.Hooks.ResolveErrorHTTPStatus; mapStatus != nil {
			status = mapStatus(allowErr)
		}
		if status == http.StatusForbidden {
			debugf("masque tcp connect policy denied host=%s port=%s status=403 error_class=policy err=%v", targetHost, targetPort, allowErr)
		} else {
			debugf("masque tcp connect resolve failed host=%s port=%s status=502 error_class=%s err=%v", targetHost, targetPort, session.ClassifyError(errors.Join(session.ErrTCPDial, allowErr)), allowErr)
		}
		w.WriteHeader(status)
		return
	}
	allowPort := h.Hooks.AllowTCPPort
	if allowPort == nil || !allowPort(targetPort, host.Options.AllowedTargetPorts, host.Options.BlockedTargetPorts) {
		debugf("masque tcp connect policy denied host=%s port=%s status=403 error_class=policy err=port_policy_denied", targetHost, targetPort)
		w.WriteHeader(http.StatusForbidden)
		return
	}
	portNum, portErr := strconv.ParseUint(targetPort, 10, 16)
	if portErr != nil || portNum == 0 || portNum > 65535 {
		debugf("masque tcp connect parse denied status=400 error_class=misconfig err=invalid_port port=%s", targetPort)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	dialSerial := h.Hooks.DialTCPTargetSerial
	if dialSerial == nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	var resolvedHost string
	debugf("masque tcp connect dial start host=%s resolved_addrs=%v port=%s", targetHost, resolvedAddrs, targetPort)
	var targetConn net.Conn
	var dialErr error
	if len(resolvedAddrs) == 0 {
		dialAddrFn := h.Hooks.OnwardTCPDialAddr
		if dialAddrFn == nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		dialAddr := dialAddrFn(targetHost, uint16(portNum))
		targetConn, dialErr = host.Dialer.DialContext(r.Context(), "tcp", dialAddr)
		resolvedHost = targetHost
	} else {
		var dialedAddr netip.Addr
		targetConn, dialedAddr, dialErr = dialSerial(r.Context(), host.Dialer, resolvedAddrs, uint16(portNum))
		resolvedHost = dialedAddr.String()
	}
	if dialErr != nil {
		debugf("masque tcp connect dial failed host=%s resolved_addrs=%v port=%s status=502 error_class=%s err=%v", targetHost, resolvedAddrs, targetPort, session.ClassifyError(errors.Join(session.ErrTCPDial, dialErr)), dialErr)
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	defer targetConn.Close()
	relay.TuneTCPOutbound(targetConn)
	_ = http.NewResponseController(w).EnableFullDuplex()
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	if flusher != nil {
		flusher.Flush()
	}
	debugf("masque tcp connect accepted host=%s resolved_host=%s port=%s status=200", targetHost, resolvedHost, targetPort)
	relayErr := relay.TCPForward(r.Context(), targetConn, r.Body, w)
	if relayErr != nil && !errors.Is(relayErr, io.EOF) && !errors.Is(relayErr, context.Canceled) {
		debugf("masque tcp relay finished host=%s resolved_host=%s port=%s status=relay_error error_class=relay_io err=%v", targetHost, resolvedHost, targetPort, relayErr)
		return
	}
	debugf("masque tcp relay finished host=%s resolved_host=%s port=%s status=ok", targetHost, resolvedHost, targetPort)
}

// ParseTCPTargetFromRequest extracts target host/port from a CONNECT request path (path-only match).
// When path_obfuscation is enabled, the {opaque} segment is opened with the baked-in key.
func ParseTCPTargetFromRequest(r *http.Request, template *uritemplate.Template, obfuscation bool) (string, string, error) {
	if r.Method != http.MethodConnect {
		return "", "", E.New("expected CONNECT request")
	}
	templateURL, err := url.Parse(template.Raw())
	if err != nil {
		return "", "", E.Cause(err, "parse tcp path template")
	}
	var candidates []string
	appendCandidate := func(s string) {
		s = strings.TrimSpace(s)
		if s != "" {
			candidates = append(candidates, s)
		}
	}
	appendCandidate(r.URL.String())
	if path := strings.TrimSpace(r.URL.Path); path != "" {
		if q := strings.TrimSpace(r.URL.RawQuery); q != "" {
			appendCandidate(path + "?" + q)
		} else {
			appendCandidate(path)
		}
	}
	appendCandidate(r.RequestURI)
	requestURIWithAuthority := ""
	if auth := strings.TrimSpace(r.Host); auth != "" {
		switch requestURI := strings.TrimSpace(r.RequestURI); {
		case requestURI == "":
		case strings.HasPrefix(strings.ToLower(requestURI), "http://"),
			strings.HasPrefix(strings.ToLower(requestURI), "https://"):
			requestURIWithAuthority = requestURI
		default:
			if !strings.HasPrefix(requestURI, "/") {
				requestURI = "/" + requestURI
			}
			scheme := strings.TrimSpace(templateURL.Scheme)
			if scheme == "" {
				scheme = "https"
			}
			requestURIWithAuthority = scheme + "://" + auth + requestURI
		}
	}
	appendCandidate(requestURIWithAuthority)
	// Also try template authority + path so path-only RequestURI still matches full URI templates.
	if templateURL.Host != "" {
		scheme := strings.TrimSpace(templateURL.Scheme)
		if scheme == "" {
			scheme = "https"
		}
		requestURI := strings.TrimSpace(r.RequestURI)
		switch {
		case requestURI == "":
		case strings.HasPrefix(strings.ToLower(requestURI), "http://"),
			strings.HasPrefix(strings.ToLower(requestURI), "https://"):
		default:
			if !strings.HasPrefix(requestURI, "/") {
				requestURI = "/" + requestURI
			}
			appendCandidate(scheme + "://" + templateURL.Host + requestURI)
		}
		if p := strings.TrimSpace(r.URL.Path); p != "" {
			if !strings.HasPrefix(p, "/") {
				p = "/" + p
			}
			appendCandidate(scheme + "://" + templateURL.Host + p)
		}
	}

	var host, port, opaque string
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		match := template.Match(candidate)
		host = strings.TrimSpace(match.Get("target_host").String())
		port = strings.TrimSpace(match.Get("target_port").String())
		opaque = strings.TrimSpace(match.Get("opaque").String())
		if opaque != "" || (host != "" && port != "") {
			break
		}
	}
	if opaque != "" {
		if !obfuscation {
			return "", "", E.New("opaque path segment requires path_obfuscation")
		}
		h, p, openErr := pathbuild.OpenHostPort(pathbuild.ActiveKey(true), opaque)
		if openErr != nil {
			return "", "", openErr
		}
		return h, strconv.Itoa(int(p)), nil
	}
	if host == "" || port == "" {
		return "", "", E.New("invalid tcp target")
	}
	if parsed, err := strconv.Atoi(port); err != nil || parsed <= 0 || parsed > 65535 {
		return "", "", E.New("invalid tcp target port")
	}
	return host, port, nil
}

// extendedConnectProtocol reads :protocol (H2 Header) or Proto (H3/quic-go).
func extendedConnectProtocol(r *http.Request) string {
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
