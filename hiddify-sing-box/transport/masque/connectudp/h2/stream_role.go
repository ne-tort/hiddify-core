package h2

import (
	"errors"
	"net/http"

	cudpasym "github.com/sagernet/sing-box/transport/masque/connectudp/asym"
)

const (
	MasqueUDPStreamRoleHeader = cudpasym.StreamRoleHeader
	MasqueUDPMuxKeyHeader     = cudpasym.MuxKeyHeader
	StreamRoleDownload        = cudpasym.StreamRoleDownload
	StreamRoleUpload          = cudpasym.StreamRoleUpload
)

// ErrMissingMuxKey is returned when asymmetric legs omit Masque-Udp-Mux-Key.
var ErrMissingMuxKey = cudpasym.ErrMissingMuxKey

// NewUDPMuxSessionKey returns a per-session mux correlation id for asymmetric legs.
func NewUDPMuxSessionKey() (string, error) {
	return cudpasym.NewMuxSessionKey()
}

// StreamRoleFromRequest returns the asymmetric leg role when set; empty means full bidi ServeH2.
func StreamRoleFromRequest(r *http.Request) string {
	return cudpasym.StreamRoleFromRequest(r)
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
func SessionKeyFromRequest(r *http.Request, targetAddr string) (sessionKey, error) {
	k, err := cudpasym.SessionKeyFromRequest(r, targetAddr)
	if err != nil {
		return sessionKey{}, err
	}
	if k.Mux == "" {
		return sessionKey{}, nil
	}
	return sessionKey{mux: k.Mux, target: k.Target}, nil
}

// RequireSessionKey returns an error when role is set but mux key parsing fails.
func RequireSessionKey(r *http.Request, targetAddr string) (sessionKey, error) {
	if StreamRoleFromRequest(r) == "" {
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
	return cudpasym.IsMissingMuxKey(err)
}

// IsDuplicateDownloadSession reports whether err is ErrDuplicateDownloadSession.
func IsDuplicateDownloadSession(err error) bool {
	return errors.Is(err, ErrDuplicateDownloadSession)
}
