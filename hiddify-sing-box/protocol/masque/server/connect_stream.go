package server

import (
	"context"
	"errors"
	"fmt"
	"github.com/sagernet/sing-box/transport/masque/session"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/masque/relay"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/yosida95/uritemplate/v3"
)

// TCPConnectHost carries CONNECT-stream handler dependencies from the parent endpoint.
type TCPConnectHost struct {
	Options   option.MasqueEndpointOptions
	Logger    log.ContextLogger
	Dialer    net.Dialer
	Authorize func(*http.Request) bool
	// AuthorityMatches checks :authority vs template URL host (loopback placeholder relax).
	AuthorityMatches func(templateHost, requestHost string, relax bool) bool
}

// HandleTCPConnectRequest serves RFC 8441 Extended CONNECT over the TCP template path.
func HandleTCPConnectRequest(host TCPConnectHost, w http.ResponseWriter, r *http.Request, tcpTemplate *uritemplate.Template, relaxedTCPAuthority bool) {
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
	// RFC 8441 Extended CONNECT over HTTP/2 sets :protocol. Our CONNECT-stream client uses HTTP/2
	// (see transport/masque/stream/dial_h2.go). HTTP/3 CONNECT-stream peers typically omit
	// :protocol while Proto carries HTTP/3 — treat empty header as compat. Reject misuse such
	// as connect-udp/connect-ip targeting the tcp template early (400), before policy/dial work.
	if p := strings.TrimSpace(r.Header.Get(":protocol")); p != "" && !strings.EqualFold(p, "HTTP/2") {
		debugf("masque tcp connect denied status=400 error_class=bad_extended_protocol proto=%q", p)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	targetHost, targetPort, parseErr := ParseTCPTargetFromRequest(r, tcpTemplate, relaxedTCPAuthority, host.AuthorityMatches)
	if parseErr != nil {
		debugf("masque tcp connect parse denied status=400 error_class=misconfig err=%v", parseErr)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	resolvedHost, allowErr := ResolveTCPTargetForDial(r.Context(), targetHost, host.Options.AllowPrivateTargets)
	if allowErr != nil {
		debugf("masque tcp connect policy denied host=%s port=%s status=403 error_class=policy err=%v", targetHost, targetPort, allowErr)
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if !AllowTCPPort(targetPort, host.Options.AllowedTargetPorts, host.Options.BlockedTargetPorts) {
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
	dialAddr := OnwardTCPDialAddr(resolvedHost, uint16(portNum))
	debugf("masque tcp connect dial start host=%s resolved_host=%s port=%s dial_addr=%s", targetHost, resolvedHost, targetPort, dialAddr)
	targetConn, dialErr := host.Dialer.DialContext(r.Context(), "tcp", dialAddr)
	if dialErr != nil {
		debugf("masque tcp connect dial failed host=%s resolved_host=%s port=%s status=502 error_class=%s err=%v", targetHost, resolvedHost, targetPort, session.ClassifyError(errors.Join(session.ErrTCPDial, dialErr)), dialErr)
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	relay.TuneTCPOutbound(targetConn)
	defer targetConn.Close()
	// RFC 8441 CONNECT-stream: relay onward TCP→response while request body may still be idle
	// (iperf3 waits for server banner before sending). Without full-duplex the HTTP stack can
	// block response DATA until the request body is consumed (TUN bench hang at 0 Mbit/s).
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

// ResolveTCPTargetForDial applies private-target policy before onward TCP dial.
func ResolveTCPTargetForDial(ctx context.Context, host string, allowPrivateTargets bool) (string, error) {
	if allowPrivateTargets {
		return strings.Trim(strings.TrimSpace(host), "[]"), nil
	}
	trimmedHost := strings.Trim(strings.TrimSpace(host), "[]")
	lowerHost := strings.ToLower(trimmedHost)
	if lowerHost == "" || lowerHost == "localhost" || strings.HasSuffix(lowerHost, ".local") {
		return "", E.New("private target denied")
	}
	addr, err := netip.ParseAddr(trimmedHost)
	if err != nil {
		resolver := net.DefaultResolver
		resolveCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		resolved, lookupErr := resolver.LookupNetIP(resolveCtx, "ip", trimmedHost)
		if lookupErr != nil || len(resolved) == 0 {
			return "", E.New("failed to resolve tcp target")
		}
		var chosen string
		for _, rip := range resolved {
			if rip.IsLoopback() || rip.IsPrivate() || rip.IsMulticast() || rip.IsLinkLocalUnicast() || rip.IsLinkLocalMulticast() || rip.IsUnspecified() {
				return "", E.New("private target denied")
			}
			if chosen == "" {
				chosen = rip.String()
			}
		}
		if chosen == "" {
			return "", E.New("failed to select resolved tcp target")
		}
		return chosen, nil
	}
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsMulticast() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsUnspecified() {
		return "", E.New("private target denied")
	}
	return addr.String(), nil
}

// AllowTCPPort enforces optional allow/deny port lists on CONNECT-stream targets.
func AllowTCPPort(portRaw string, allowList []uint16, denyList []uint16) bool {
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

// ParseTCPTargetFromRequest extracts target_host/target_port from a CONNECT request URI.
func ParseTCPTargetFromRequest(r *http.Request, template *uritemplate.Template, relaxedTCPAuthority bool, authorityMatches func(templateHost, requestHost string, relax bool) bool) (string, string, error) {
	if r.Method != http.MethodConnect {
		return "", "", E.New("expected CONNECT request")
	}
	templateURL, err := url.Parse(template.Raw())
	if err != nil {
		return "", "", E.Cause(err, "parse tcp template")
	}
	if templateURL.Host != "" && authorityMatches != nil && !authorityMatches(templateURL.Host, strings.TrimSpace(r.Host), relaxedTCPAuthority) {
		return "", "", E.New("CONNECT authority does not match TCP template host")
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
	// Parity with connect-ip-go matchTemplateRequestValues: some HTTP/2 stacks surface
	// path-only RequestURI; absolute URI templates need https://authority + normalized path.
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
	if relaxedTCPAuthority && templateURL.Host != "" {
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
	var host, port string
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		match := template.Match(candidate)
		host = strings.TrimSpace(match.Get("target_host").String())
		port = strings.TrimSpace(match.Get("target_port").String())
		if host != "" && port != "" {
			break
		}
	}
	if host == "" || port == "" {
		return "", "", E.New("invalid tcp target")
	}
	if parsed, err := strconv.Atoi(port); err != nil || parsed <= 0 || parsed > 65535 {
		return "", "", E.New("invalid tcp target port")
	}
	return host, port, nil
}
