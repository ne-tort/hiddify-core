package h2

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
)

// MasqueUDPStreamRoleHeader tags asymmetric CONNECT-UDP legs (download-primary vs upload-only).
const MasqueUDPStreamRoleHeader = "Masque-Udp-Stream-Role"

// MasqueUDPMuxKeyHeader correlates asymmetric legs across separate TCP/H2 connections.
const MasqueUDPMuxKeyHeader = "Masque-Udp-Mux-Key"

const (
	StreamRoleDownload = "download"
	StreamRoleUpload   = "upload"
)

// NewUDPMuxSessionKey returns a per-session mux correlation id for asymmetric legs.
func NewUDPMuxSessionKey() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// StreamRoleFromRequest returns the asymmetric leg role when set; empty means full bidi ServeH2.
func StreamRoleFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	return strings.TrimSpace(r.Header.Get(MasqueUDPStreamRoleHeader))
}

type sessionKey struct {
	mux    string
	target string
}

// AsymmetricSessionKey correlates asymmetric CONNECT-UDP legs across streams.
type AsymmetricSessionKey struct {
	Mux    string
	Target string
}

func (k sessionKey) export() AsymmetricSessionKey {
	return AsymmetricSessionKey{Mux: k.mux, Target: k.target}
}

// AsymmetricSessionKeyFromRequest builds the mux key when stream role is set.
func AsymmetricSessionKeyFromRequest(r *http.Request, targetAddr string) (AsymmetricSessionKey, error) {
	key, err := RequireSessionKey(r, targetAddr)
	if err != nil {
		return AsymmetricSessionKey{}, err
	}
	if StreamRoleFromRequest(r) == "" {
		return AsymmetricSessionKey{}, nil
	}
	return key.export(), nil
}

// SessionKeyFromRequest builds the server session key for asymmetric CONNECT-UDP legs.
// Masque-Udp-Mux-Key is required when stream role is set.
func SessionKeyFromRequest(r *http.Request, targetAddr string) (sessionKey, error) {
	role := StreamRoleFromRequest(r)
	if role == "" {
		return sessionKey{}, nil
	}
	session := ""
	if r != nil {
		session = strings.TrimSpace(r.Header.Get(MasqueUDPMuxKeyHeader))
	}
	if session == "" {
		return sessionKey{}, ErrMissingMuxKey
	}
	return sessionKey{mux: session, target: targetAddr}, nil
}

// RequireSessionKey returns an error when role is set but mux key parsing fails.
func RequireSessionKey(r *http.Request, targetAddr string) (sessionKey, error) {
	role := StreamRoleFromRequest(r)
	if role == "" {
		return sessionKey{}, nil
	}
	key, err := SessionKeyFromRequest(r, targetAddr)
	if err != nil {
		return sessionKey{}, err
	}
	if key.mux == "" {
		return sessionKey{}, ErrMissingMuxKey
	}
	return key, nil
}

// IsMissingMuxKey reports whether err is ErrMissingMuxKey.
func IsMissingMuxKey(err error) bool {
	return errors.Is(err, ErrMissingMuxKey)
}

// IsDuplicateDownloadSession reports whether err is ErrDuplicateDownloadSession.
func IsDuplicateDownloadSession(err error) bool {
	return errors.Is(err, ErrDuplicateDownloadSession)
}
