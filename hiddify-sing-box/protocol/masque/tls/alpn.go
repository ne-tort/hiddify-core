package masquetls

import (
	"strings"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	ALPNH2     = "h2"
	ALPNH3     = "h3"
	ALPNHTTP11 = "http/1.1"
)

// ContainsALPN reports whether token is present (case-sensitive, wire tokens).
func ContainsALPN(list []string, token string) bool {
	for _, p := range list {
		if p == token {
			return true
		}
	}
	return false
}

// CopyALPNs returns a defensive copy (nil if empty).
func CopyALPNs(list []string) []string {
	if len(list) == 0 {
		return nil
	}
	out := make([]string, len(list))
	copy(out, list)
	return out
}

// RequireALPNToken errors if list is non-empty and missing token.
func RequireALPNToken(list []string, token, field string) error {
	if len(list) == 0 {
		return nil
	}
	if !ContainsALPN(list, token) {
		return E.New("masque: ", field, " must contain ", token, " when set (got ", strings.Join(list, ","), ")")
	}
	return nil
}

// DefaultOutboundALPN returns layer defaults when JSON alpn is empty.
// auto (dual H3↔H2) advertises both application protocols on the shared TLS surface.
func DefaultOutboundALPN(httpLayer string) []string {
	switch NormalizeHTTPLayer(httpLayer) {
	case option.MasqueHTTPLayerH2:
		return []string{ALPNH2}
	case option.MasqueHTTPLayerAuto:
		return []string{ALPNH3, ALPNH2, ALPNHTTP11}
	default: // h3 (empty http_layer product default)
		return []string{ALPNH3}
	}
}

// DefaultInboundALPN returns server defaults when tls.alpn is empty.
func DefaultInboundALPN(httpLayerHint string) []string {
	switch NormalizeHTTPLayer(httpLayerHint) {
	case option.MasqueHTTPLayerH2:
		return DefaultH2ServerTCPALPN()
	default: // h3 / auto / dual listen — QUIС + TCP collateral
		return []string{ALPNH3, ALPNH2, ALPNHTTP11}
	}
}

// ResolveOutboundALPN: empty → layer default; non-empty → copy (caller validates tokens).
func ResolveOutboundALPN(alpn []string, httpLayer string) []string {
	if len(alpn) == 0 {
		return DefaultOutboundALPN(httpLayer)
	}
	return CopyALPNs(alpn)
}

// EnsureH2InALPN never drops user tokens; if h2 missing, appends it (H2 dial necessity only).
func EnsureH2InALPN(existing []string) []string {
	if len(existing) == 0 {
		return []string{ALPNH2}
	}
	if ContainsALPN(existing, ALPNH2) {
		return CopyALPNs(existing)
	}
	return append(CopyALPNs(existing), ALPNH2)
}

// EnsureH3InALPN never drops user tokens; if h3 missing, appends it (QUIC dial necessity only).
func EnsureH3InALPN(existing []string) []string {
	if len(existing) == 0 {
		return []string{ALPNH3}
	}
	if ContainsALPN(existing, ALPNH3) {
		return CopyALPNs(existing)
	}
	return append(CopyALPNs(existing), ALPNH3)
}

// FilterTCPALPN drops QUIС-only "h3" from lists used on TCP TLS.
// Shared outbound/inbound ALPN for dual stacks often include h3; advertising it on TCP
// makes crypto/tls negotiate ALPN=h3 (server preference) and HTTP/2 preface fails with EOF.
func FilterTCPALPN(existing []string) []string {
	if len(existing) == 0 {
		return nil
	}
	out := make([]string, 0, len(existing))
	for _, p := range existing {
		if p == ALPNH3 {
			continue
		}
		out = append(out, p)
	}
	return out
}

// ApplyH2ClientNextProtos prepares ClientHello ALPN for the H2 TCP path.
// Empty → ["h2"]; strips h3; preserves other tokens and ensures h2 is present.
func ApplyH2ClientNextProtos(existing []string) []string {
	return EnsureH2InALPN(FilterTCPALPN(existing))
}

// DefaultH2ServerTCPALPN is used when TCP collateral has no NextProtos.
func DefaultH2ServerTCPALPN() []string {
	return []string{ALPNH2, ALPNHTTP11}
}

// ApplyH2ServerTCPNextProtos: empty → default h2+http/1.1; strips h3; else must contain h2.
func ApplyH2ServerTCPNextProtos(existing []string) ([]string, error) {
	filtered := FilterTCPALPN(existing)
	if len(filtered) == 0 {
		return DefaultH2ServerTCPALPN(), nil
	}
	if err := RequireALPNToken(filtered, ALPNH2, "tls.alpn (server TCP)"); err != nil {
		return nil, err
	}
	return CopyALPNs(filtered), nil
}
