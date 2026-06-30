// Package asym holds CONNECT-UDP asymmetric leg role headers (shared H2/H3, no relay import).
package asym

import (
	"errors"
	"net/http"
	"strings"
)

const (
	StreamRoleHeader     = "Masque-Udp-Stream-Role"
	MuxKeyHeader         = "Masque-Udp-Mux-Key"
	StreamRoleDownload   = "download"
	StreamRoleUpload     = "upload"
)

// ErrMissingMuxKey is returned when asymmetric legs omit Masque-Udp-Mux-Key.
var ErrMissingMuxKey = errors.New("masque connect-udp: missing Masque-Udp-Mux-Key")

// SessionKey correlates asymmetric CONNECT-UDP legs across streams.
type SessionKey struct {
	Mux    string
	Target string
}

// StreamRoleFromRequest returns the asymmetric leg role when set; empty means full bidi.
func StreamRoleFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	return strings.TrimSpace(r.Header.Get(StreamRoleHeader))
}

// SessionKeyFromRequest builds the mux key when stream role is set.
func SessionKeyFromRequest(r *http.Request, targetAddr string) (SessionKey, error) {
	if StreamRoleFromRequest(r) == "" {
		return SessionKey{}, nil
	}
	if r == nil {
		return SessionKey{}, ErrMissingMuxKey
	}
	mux := strings.TrimSpace(r.Header.Get(MuxKeyHeader))
	if mux == "" {
		return SessionKey{}, ErrMissingMuxKey
	}
	return SessionKey{Mux: mux, Target: targetAddr}, nil
}

// IsMissingMuxKey reports whether err is ErrMissingMuxKey.
func IsMissingMuxKey(err error) bool {
	return errors.Is(err, ErrMissingMuxKey)
}
