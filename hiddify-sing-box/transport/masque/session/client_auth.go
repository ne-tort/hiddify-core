package session

import (
	"encoding/base64"
	"net/http"
	"strings"
)

// WarpConnectStreamBearerToken chooses Authorization Bearer for CONNECT-stream and CONNECT-UDP/IP
// overlays that share the same policy. Explicit server_token wins.
//
// Consumer WARP MASQUE dataplane matches dialWarpConnectIPTunnel / usque: CONNECT-IP authenticates via
// mTLS (WarpMasqueClientCert) without device Bearer on the QUIC overlay. Sending profile auth_token on
// masque/tcp CONNECT-stream triggers 403 from the edge while the same Bearer is omitted on cf-connect-ip.
// Generic masque without WARP client cert may still attach WarpMasqueDeviceBearerToken when configured.
// CONNECT-IP dial uses the same rules via connectip.DialAuthFromInput.
func WarpConnectStreamBearerToken(opts ClientOptions) string {
	if t := strings.TrimSpace(opts.ServerToken); t != "" {
		return t
	}
	if len(opts.WarpMasqueClientCert.Certificate) > 0 {
		return ""
	}
	return strings.TrimSpace(opts.WarpMasqueDeviceBearerToken)
}

// ClientBasicAuthHeader returns an RFC 7617 Basic Authorization header value.
func ClientBasicAuthHeader(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(strings.TrimSpace(user)+":"+pass))
}

// SetAuthorizationHeader sets Bearer or Basic Authorization on h for MASQUE CONNECT requests.
func SetAuthorizationHeader(h http.Header, opts ClientOptions) {
	if u := strings.TrimSpace(opts.ClientBasicUsername); u != "" {
		h.Set("Authorization", ClientBasicAuthHeader(u, opts.ClientBasicPassword))
		return
	}
	if tok := WarpConnectStreamBearerToken(opts); tok != "" {
		h.Set("Authorization", "Bearer "+tok)
	}
}
