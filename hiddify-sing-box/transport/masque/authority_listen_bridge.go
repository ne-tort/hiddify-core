package masque

import (
	"crypto/tls"

	"github.com/sagernet/sing-box/transport/masque/session"
)

type (
	// AuthorityListenOptions configures a thin-parity HTTP/3 CONNECT authority listener.
	AuthorityListenOptions = session.AuthorityListenOptions
	// AuthorityHTTPServer is a minimal HTTP/3 server (masque-thin-server parity).
	AuthorityHTTPServer = session.AuthorityHTTPServer
)

// StartAuthorityHTTPServer listens UDP and serves HTTP/3 like masque-thin-server.
func StartAuthorityHTTPServer(opts AuthorityListenOptions) (*AuthorityHTTPServer, error) {
	return session.StartAuthorityHTTPServer(opts)
}

// LoadAuthorityTLSFromPEM loads server TLS like masque-thin-server and returns http3-ready config.
func LoadAuthorityTLSFromPEM(certPath, keyPath string) (*tls.Config, error) {
	return session.LoadAuthorityTLSFromPEM(certPath, keyPath)
}
