package connectip

import (
	"encoding/base64"
	"net/http"
	"strings"
)

// DialAuth carries bearer/basic credentials shared by CONNECT-IP H2 and H3 dial overlays.
type DialAuth struct {
	BearerToken         string
	ExtraRequestHeaders http.Header
}

// DialAuthFromCredentials resolves CONNECT-IP dial auth from session options.
// Basic credentials override Bearer when username is non-empty.
func DialAuthFromCredentials(serverToken, basicUser, basicPass string) DialAuth {
	token := strings.TrimSpace(serverToken)
	var extra http.Header
	if u := strings.TrimSpace(basicUser); u != "" {
		token = ""
		extra = make(http.Header)
		extra.Set("Authorization", dialBasicAuthHeader(u, basicPass))
	}
	return DialAuth{BearerToken: token, ExtraRequestHeaders: extra}
}

func dialBasicAuthHeader(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(strings.TrimSpace(user)+":"+pass))
}
