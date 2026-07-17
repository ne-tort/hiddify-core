package connectip

import (
	"crypto/tls"
	"encoding/base64"
	"net/http"
	"strings"
)

// DialAuth carries bearer/basic credentials shared by CONNECT-IP H2 and H3 dial overlays.
type DialAuth struct {
	BearerToken         string
	ExtraRequestHeaders http.Header
}

// DialAuthInput mirrors CONNECT-stream auth fields for CONNECT-IP parity
// (server_token / basic / WARP device bearer + mTLS omit).
type DialAuthInput struct {
	ServerToken                 string
	ClientBasicUsername         string
	ClientBasicPassword         string
	WarpMasqueDeviceBearerToken string
	// WarpMasqueClientCert non-empty Certificate means mTLS: omit device bearer (same as stream).
	WarpMasqueClientCert tls.Certificate
}

// DialAuthFromCredentials resolves CONNECT-IP dial auth from server_token / Basic only.
// Prefer DialAuthFromInput for full stream parity (WARP device bearer + mTLS omit).
func DialAuthFromCredentials(serverToken, basicUser, basicPass string) DialAuth {
	return DialAuthFromInput(DialAuthInput{
		ServerToken:         serverToken,
		ClientBasicUsername: basicUser,
		ClientBasicPassword: basicPass,
	})
}

// DialAuthFromInput resolves CONNECT-IP dial auth with the same precedence as
// session.SetAuthorizationHeader / WarpConnectStreamBearerToken:
// Basic wins; else server_token; else omit device bearer when mTLS cert present; else device bearer.
func DialAuthFromInput(in DialAuthInput) DialAuth {
	if u := strings.TrimSpace(in.ClientBasicUsername); u != "" {
		extra := make(http.Header)
		extra.Set("Authorization", dialBasicAuthHeader(u, in.ClientBasicPassword))
		return DialAuth{ExtraRequestHeaders: extra}
	}
	token := connectIPBearerToken(in)
	return DialAuth{BearerToken: token}
}

// connectIPBearerToken matches session.WarpConnectStreamBearerToken.
func connectIPBearerToken(in DialAuthInput) string {
	if t := strings.TrimSpace(in.ServerToken); t != "" {
		return t
	}
	if len(in.WarpMasqueClientCert.Certificate) > 0 {
		return ""
	}
	return strings.TrimSpace(in.WarpMasqueDeviceBearerToken)
}

func dialBasicAuthHeader(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(strings.TrimSpace(user)+":"+pass))
}
