package masque

import (
	"errors"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/transport/masque/httpx"
)

func isDataplaneMarker(msg string) bool {
	sl := strings.ToLower(msg)
	for _, sub := range []string{
		"masque h2 dataplane",
		"masque connect-ip h2 dataplane",
		"masque h2: dataplane",
		"masque connect-ip h2: dataplane",
		"masque h3 dataplane",
		"masque h3: dataplane",
		"masque connect-ip h3 dataplane",
		"masque connect-ip h3: dataplane",
		"masque connect-udp h3 skip-capsules",
	} {
		if strings.Contains(sl, sub) {
			return true
		}
	}
	return false
}

func handshakeBucket(class string) bool {
	switch class {
	case "h2_masque_handshake", "h3_extended_connect", "h3_datagrams",
		"h2_extended_connect_rfc8441", "quic_idle_timeout", "quic_tls":
		return true
	default:
		return false
	}
}

// TestOverlayFallbackMatrixClassifySync keeps httpx.IsLayerSwitchableFailure aligned with
// ClassifyMasqueFailure for the shared overlay fallback contract (L0 session).
func TestOverlayFallbackMatrixClassifySync(t *testing.T) {
	cases := []struct {
		err            string
		wantSwitchable bool
	}{
		{"masque h2 dataplane connect-udp capsule: truncated", false},
		{"masque connect-ip h2 dataplane: DATAGRAM capsule truncated", false},
		{"masque h3 dataplane connect-stream read: QUIC extended connect noise", false},
		{"masque connect-udp h3 skip-capsules: type=1 capsule exceeds 65536 bytes", false},
		{"masque h2: CONNECT-UDP status 401", false},
		{"connect-ip: server responded with 403", false},
		{"connect-ip: server responded with 407", false},
		{"401 Unauthorized", false},
		{"http3: server didn't enable Extended CONNECT", true},
		{"masque h2: roundtrip: EOF", true},
		{"http2: server rejected ENABLE_CONNECT_PROTOCOL", true},
		{"http3: server didn't enable Datagrams for this connection", true},
		{"no recent network activity", true},
		{"tls: handshake failure", true},
		{"dial udp 192.0.2.1:1401: connection refused", true},
		{"read tcp: connection timed out", true},
	}
	for _, tc := range cases {
		err := errors.New(tc.err)
		class := ClassifyMasqueFailure(err)
		got := httpx.IsLayerSwitchableFailure(err)
		if got != tc.wantSwitchable {
			t.Errorf("%q: classify=%q switchable=%v want %v", tc.err, class, got, tc.wantSwitchable)
		}
		if class == "connect_http_auth" && got {
			t.Errorf("%q: connect_http_auth must not be switchable", tc.err)
		}
		if isDataplaneMarker(tc.err) && got {
			t.Errorf("%q: dataplane marker must not be switchable (classify=%q)", tc.err, class)
		}
		if handshakeBucket(class) && !got {
			t.Errorf("%q: handshake bucket %q must be switchable", tc.err, class)
		}
	}
}
