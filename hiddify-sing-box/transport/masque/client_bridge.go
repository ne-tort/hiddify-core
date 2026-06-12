package masque

import (
	"crypto/tls"
	"net/http"

	"github.com/quic-go/quic-go/http3"
	"github.com/sagernet/sing-box/transport/masque/session"
)

func warpMasqueConnectStreamBearerToken(opts ClientOptions) string {
	return session.WarpConnectStreamBearerToken(opts)
}

func masqueClientBasicAuthHeader(user, pass string) string {
	return session.ClientBasicAuthHeader(user, pass)
}

func setMasqueAuthorizationHeader(h http.Header, opts ClientOptions) {
	session.SetAuthorizationHeader(h, opts)
}

func masqueClientTLSConfig(opts ClientOptions) *tls.Config {
	return session.ClientTLSConfig(opts)
}

func applyWarpMasqueHTTP3TransportFields(tr *http3.Transport, opts ClientOptions) {
	session.ApplyWarpHTTP3TransportFields(tr, opts)
}
