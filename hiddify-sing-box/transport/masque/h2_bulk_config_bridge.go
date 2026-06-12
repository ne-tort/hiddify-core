package masque

import (
	mh2 "github.com/sagernet/sing-box/transport/masque/h2"
	"golang.org/x/net/http2"
)

// MasqueBulkHTTP2ServerConfig returns http2.Server settings for MASQUE Extended CONNECT listeners.
func MasqueBulkHTTP2ServerConfig() *http2.Server {
	return mh2.BulkHTTP2ServerConfig()
}
