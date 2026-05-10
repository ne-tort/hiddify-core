package masque

import (
	"strings"
)

// ClassifyMasqueFailure returns a short machine-oriented reason key for dataplane/session start
// diagnostics (no secrets). Used by generic `masque` and `warp_masque` alike.
func ClassifyMasqueFailure(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "Extended CONNECT"):
		return "h3_extended_connect"
	case strings.Contains(s, "didn't enable datagrams"), strings.Contains(s, "didn't enable Datagrams"):
		return "h3_datagrams"
	case strings.Contains(s, "no recent network activity"):
		return "quic_idle_timeout"
	case strings.Contains(s, "tls: handshake failure"), strings.Contains(s, "CRYPTO_ERROR"):
		return "quic_tls"
	case strings.Contains(s, "401"), strings.Contains(s, "Unauthorized"):
		return "connect_http_auth"
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
	case "connect_http_auth", "h3_extended_connect", "h3_datagrams":
		return false
	default:
		return true
	}
}
