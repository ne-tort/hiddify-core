package masque

import (
	"regexp"
	"strings"
)

// HTTP status tokens embedded in error text must not use naive substring checks:
// port numbers like 1401/84403 contain "401"/"403" and would false-classify as auth.
var masqueHTTPAuthStatusRE = regexp.MustCompile(`\b(401|403|407)\b`)

// ClassifyMasqueFailure returns a short machine-oriented reason key for dataplane/session start
// diagnostics (no secrets). Used by generic `masque` and `warp_masque` alike.
func ClassifyMasqueFailure(err error) string {
	if err == nil {
		return ""
	}
	sl := strings.ToLower(err.Error())
	switch {
	// Post-handshake H2 dataplane diagnostics use "masque h2 dataplane …" / "… connect-udp server …"
	// (no "masque h2:") so they don't drive http_layer_fallback. Explicitly keep them out of the
	// handshake bucket — including colon typos ("masque h2: dataplane …") that would otherwise match.
	// Match on sl so mixed-case library/wrapper text does not fall through to handshake/http2 buckets.
	case strings.Contains(sl, "masque h2 dataplane"),
		strings.Contains(sl, "masque connect-ip h2 dataplane"),
		strings.Contains(sl, "masque h2: dataplane"),
		strings.Contains(sl, "masque connect-ip h2: dataplane"),
		strings.Contains(sl, "masque h3 dataplane"),
		strings.Contains(sl, "masque h3: dataplane"),
		strings.Contains(sl, "masque connect-ip h3 dataplane"),
		strings.Contains(sl, "masque connect-ip h3: dataplane"):
		return "other"
	// CONNECT-UDP H3 request-stream capsule drain (masque-go); not an overlay/handshake metric bucket.
	case strings.Contains(sl, "masque connect-udp h3 skip-capsules"):
		return "other"
	// HTTP 401/403/407 on overlay handshake paths stringify as "masque h2: …" / "masque connect-ip h2: …";
	// auth must win over the generic masque h2 handshake bucket (WARP metrics / port policy).
	case masqueHTTPAuthStatusRE.MatchString(sl),
		strings.Contains(sl, "unauthorized"),
		strings.Contains(sl, "forbidden"),
		strings.Contains(sl, "proxy authentication required"):
		return "connect_http_auth"
	case strings.Contains(sl, "masque connect-ip h2:"), strings.Contains(sl, "masque h2:"):
		return "h2_masque_handshake"
	// golang.org/x/net/http2 client: SETTINGS without ENABLE_CONNECT_PROTOCOL=1 → RoundTrip refuses Extended CONNECT (RFC 8441).
	// Match case-insensitively: localized or wrapped errors must not fall through to the H3 "Extended CONNECT" bucket.
	case strings.Contains(sl, "extended connect not supported"):
		return "h2_extended_connect_rfc8441"
	case strings.Contains(sl, "enable_connect_protocol"), strings.Contains(sl, "enable connect protocol"):
		return "h2_extended_connect_rfc8441"
	case strings.Contains(sl, "http2:"):
		// Bare x/net/http2 errors (wrap path without masque h2:) still mean H2 overlay handshake/policy failure for metrics + WARP port policy.
		return "h2_masque_handshake"
	// H3/QUIC stack messages may use lowercase "extended connect"; datagram-plane exclusions and
	// "extended connect not supported" (RFC 8441) are handled above.
	case strings.Contains(sl, "extended connect"):
		return "h3_extended_connect"
	case strings.Contains(sl, "didn't enable datagram"):
		return "h3_datagrams"
	case strings.Contains(sl, "no recent network activity"):
		return "quic_idle_timeout"
	case strings.Contains(sl, "tls: handshake failure"), strings.Contains(sl, "crypto_error"):
		return "quic_tls"
	default:
		return "other"
	}
}

// ClassifyWarpMasqueFailure is an alias for ClassifyMasqueFailure.
func ClassifyWarpMasqueFailure(err error) string {
	return ClassifyMasqueFailure(err)
}

// IsRetryableWarpMasqueDataplanePort rotates to another UDP port candidate (e.g. 443 vs 2408).
// Errors that imply wrong host/SNI/policy should not spin ports.
func IsRetryableWarpMasqueDataplanePort(err error) bool {
	if err == nil {
		return false
	}
	switch ClassifyMasqueFailure(err) {
	case "connect_http_auth",
		"h2_masque_handshake", "h2_extended_connect_rfc8441",
		"h3_extended_connect", "h3_datagrams":
		return false
	default:
		return true
	}
}
