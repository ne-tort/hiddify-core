package masquethin

import (
	"context"
	"crypto/subtle"
	"net"
	"net/http"
	"strings"

	"github.com/sagernet/sing-box/protocol/masque/server"
)

// ServerConfig is the thin MASQUE authority server settings.
type ServerConfig struct {
	BearerToken  string
	AllowPrivate bool
}

// AuthorizeRequest checks optional Bearer token (empty token = open).
func (c ServerConfig) AuthorizeRequest(r *http.Request) bool {
	tok := strings.TrimSpace(c.BearerToken)
	if tok == "" {
		return true
	}
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return false
	}
	got := strings.TrimSpace(auth[len(prefix):])
	return subtle.ConstantTimeCompare([]byte(got), []byte(tok)) == 1
}

// ParseAuthorityTarget returns onward TCP host/port from CONNECT by authority.
func ParseAuthorityTarget(r *http.Request) (host, port string, err error) {
	return server.ParseCONNECTAuthorityTarget(r)
}

// HandleCONNECTAuthority serves RFC 9114 CONNECT https://host:port/ and relays TCP.
func HandleCONNECTAuthority(w http.ResponseWriter, r *http.Request, cfg ServerConfig, dial func(ctx context.Context, network, addr string) (net.Conn, error)) {
	policy := server.CONNECTAuthorityPolicy{
		AllowPrivateTargets: cfg.AllowPrivate,
		Authorize:           cfg.AuthorizeRequest,
	}
	server.ServeCONNECTAuthority(w, r, policy, dial)
}
