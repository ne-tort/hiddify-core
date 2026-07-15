package httpx

import (
	"errors"
	"net"
	"regexp"
	"strings"
	"sync"

	h2c "github.com/sagernet/sing-box/transport/masque/h2"
)

// Keep in sync with protocol/masque/errors_classify.go (ClassifyMasqueFailure connect_http_auth).
// Naive "401"/"403" substrings match inside port numbers (1401, 84403).
var httpAuthStatusRE = regexp.MustCompile(`\b(401|403|407)\b`)

var (
	nonSwitchableMu sync.RWMutex
	nonSwitchable   = []error{
		net.ErrClosed,
		h2c.ErrOversizedDeclared,
	}
)

// RegisterNonSwitchableSentinel adds errors that must never consume http_layer_fallback.
// Called from transport/masque init with masque-specific configuration sentinels.
func RegisterNonSwitchableSentinel(errs ...error) {
	nonSwitchableMu.Lock()
	defer nonSwitchableMu.Unlock()
	nonSwitchable = append(nonSwitchable, errs...)
}

func isRegisteredNonSwitchable(err error) bool {
	nonSwitchableMu.RLock()
	defer nonSwitchableMu.RUnlock()
	for _, sentinel := range nonSwitchable {
		if errors.Is(err, sentinel) {
			return true
		}
	}
	return false
}

// IsLayerSwitchableFailure classifies dataplane/handshake faults where trying the alternate H2/H3 overlay may help.
// Callers MUST NOT retry on authoritative HTTP auth/policy errors or explicit configuration rejects.
func IsLayerSwitchableFailure(err error) bool {
	if err == nil {
		return false
	}
	if isRegisteredNonSwitchable(err) {
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
	// Onward TCP dial failures (502/503) are per-target server errors, not H2↔H3 overlay faults.
	if strings.Contains(es, "tcp connect-stream failed: status=502") ||
		strings.Contains(es, "tcp connect-stream failed: status=503") {
		return false
	}
	// H2 CONNECT-UDP asymmetric timeout / status 503 is per-flow WAN race (STR-P2-H2-CONNECT-UDP-503),
	// not a reason to tear down shared H2 CONNECT-stream overlay (http_layer:auto poison).
	if strings.Contains(es, "connect-udp status 503") ||
		strings.Contains(es, "asymmetric upload leg timed out") ||
		strings.Contains(es, "asymmetric upload wait canceled") {
		return false
	}
	// Local graceful H3/QUIC close is often a cascade artifact from shared-session teardown,
	// not a transport-layer fault that should burn http_layer_fallback on sibling dials.
	if strings.Contains(es, "h3 error (0x0) (local)") {
		return false
	}
	switch {
	case httpAuthStatusRE.MatchString(es),
		strings.Contains(es, "unauthorized"),
		strings.Contains(es, "forbidden"),
		strings.Contains(es, "proxy authentication required"):
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
