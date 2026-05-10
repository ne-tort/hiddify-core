package masque

import (
	"errors"
	"net"
	"regexp"
	"strings"
)

// Keep in sync with protocol/masque/errors_classify.go (ClassifyMasqueFailure connect_http_auth).
// Naive "401"/"403" substrings match inside port numbers (1401, 84403).
var masqueHTTPAuthStatusRE = regexp.MustCompile(`\b(401|403|407)\b`)

// IsMasqueHTTPLayerSwitchableFailure classifies dataplane/handshake faults where trying the alternate H2/H3 overlay may help.
// Callers MUST NOT retry on authoritative HTTP auth/policy errors or explicit configuration rejects.
func IsMasqueHTTPLayerSwitchableFailure(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrConnectUDPTemplateNotConfigured) || errors.Is(err, ErrConnectIPTemplateNotConfigured) {
		return false
	}
	// Hostile varint / declared-length policy on the wire; overlay H2↔H3 does not help.
	if errors.Is(err, errMasqueH2ConnectUDPOversizedDeclared) {
		return false
	}
	// CONNECT-IP may return sentinel net.ErrClosed (e.g. receiveProxiedDatagram when closeErr is unset)
	// or *connectip.CloseError, which implements Is(net.ErrClosed). Same Error() text as syscall-style
	// "use … closed …" failures must remain switchable via substring match below — only the sentinel/opt chain.
	if errors.Is(err, net.ErrClosed) {
		return false
	}
	es := strings.ToLower(err.Error())
	// Handshake vs dataplane markers match ClassifyMasqueFailure: never burn http_layer_fallback on
	// mid-tunnel capsule/datagram faults, even if the message also contains substrings like
	// "extended connect" or "handshake" from wrapped library text.
	if strings.Contains(es, "masque h2 dataplane") ||
		strings.Contains(es, "masque connect-ip h2 dataplane") ||
		strings.Contains(es, "masque h2: dataplane") ||
		strings.Contains(es, "masque connect-ip h2: dataplane") ||
		strings.Contains(es, "masque h3 dataplane") ||
		strings.Contains(es, "masque h3: dataplane") ||
		strings.Contains(es, "masque connect-ip h3 dataplane") ||
		strings.Contains(es, "masque connect-ip h3: dataplane") ||
		// masque-go H3 CONNECT-UDP background capsule drain (third_party/masque-go); not an overlay handshake fault.
		strings.Contains(es, "masque connect-udp h3 skip-capsules") {
		return false
	}
	switch {
	case masqueHTTPAuthStatusRE.MatchString(es),
		strings.Contains(es, "unauthorized"),
		strings.Contains(es, "forbidden"),
		strings.Contains(es, "proxy authentication required"):
		return false
	case errors.Is(err, ErrAuthFailed):
		return false
	}
	// Platform-specific dial/read timeouts (notably Windows connectex / WSA) often omit "i/o timeout"
	// and "connection timed out" tokens while still satisfying net.Error.Timeout().
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.Timeout() {
		return false // same resolver+host for H2/H3; overlay flip does not fix DNS timeouts
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	switch {
	case strings.Contains(es, "extended connect"):
		return true
	case strings.Contains(es, "didn't enable datagram"),
		strings.Contains(es, "didn't enable datagrams"):
		return true
	case strings.Contains(es, "tls:"),
		strings.Contains(es, "certificate"),
		strings.Contains(es, "crypto_error"),
		strings.Contains(es, "handshake"):
		return true
	case strings.Contains(es, "i/o timeout"),
		strings.Contains(es, "deadline exceeded"),
		// Linux errno and some wrapped errors use this phrasing without the stdlib "i/o timeout" token.
		strings.Contains(es, "connection timed out"),
		strings.Contains(es, "connection refused"),
		strings.Contains(es, "network is unreachable"),
		strings.Contains(es, "no route to host"):
		return true
	case strings.Contains(es, "quic_idle_timeout"),
		strings.Contains(es, "no recent network activity"),
		strings.Contains(es, "extended connect not supported"):
		return true
	case strings.Contains(es, "masque h2:"),
		strings.Contains(es, "masque connect-ip h2:"),
		strings.Contains(es, "http2:"),
		strings.Contains(es, "connection reset"):
		return true
	// HTTP/3 CONNECT-stream rejects non-2xx as ErrTCPConnectStreamFailed + ": status=" (see dialTCPStreamHTTP3).
	// H2 attaches "masque h2:" first; match this sentinel shape so fallback can pivot H3→H2 like policy/deny HTTP codes,
	// without treating CONNECT-stream dataplane errors (prefixed masque *_dataplane connect-stream above) as switchable twice.
	case strings.Contains(es, "tcp connect-stream failed: status="):
		return true
	// H3 CONNECT-UDP (masque-go DialAddr) and H3 CONNECT-IP (connectip.Dial*) return plain "… responded with <code>"
	// without masque h2:/handshake tokens; mirror H2 paths that use "masque h2:" / "masque connect-ip h2:" prefixes.
	// 401/403 remain non-switchable via the auth substring checks above.
	case strings.Contains(es, "masque: server responded with"),
		strings.Contains(es, "connect-ip: server responded with"):
		return true
	// golang.org/x/net/http2: GOAWAY, RST_STREAM, StreamError; flipping the outer layer may
	// succeed when the TCP session dies without a QUIC-only root cause.
	case strings.Contains(es, "goaway"),
		strings.Contains(es, "rst_stream"),
		strings.Contains(es, "rststream"),
		strings.Contains(es, "stream error"):
		return true
	// Plain TLS/TCP teardown (e.g. peer reset, write after close) often has no "http2:" or
	// RFC 8441 token in the message; still worth one H2↔H3 pivot when the user enabled fallback.
	case strings.Contains(es, "broken pipe"),
		strings.Contains(es, "connection aborted"),
		strings.Contains(es, "forcibly closed"),
		// stdlib: operations on a closed TCP conn (peer half-close, race on teardown).
		strings.Contains(es, "use of closed network connection"),
		// Windows: English localized pipe/socket shutdown (distinct from wsarecv/forcibly closed).
		strings.Contains(es, "pipe is being closed"):
		return true
	default:
		return false
	}
}
