package masque

import (
	"net/url"
	"strings"
)

// MasqueTCPConnectStreamRequestURL returns the absolute URL string used for MASQUE CONNECT-stream
// HTTP/2 and HTTP/3 requests. net/url.URL.String() applies EscapedPath, which encodes `[` and `]`
// as %5B and %5D; many reverse proxies match `/tcp/[IPv6]/port` only with literal brackets and
// return HTTP 400 for percent-encoded brackets.
func MasqueTCPConnectStreamRequestURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	s := u.String()
	if strings.Contains(u.Path, "[") && strings.Contains(s, "%5B") {
		path := u.Path
		if path == "" {
			path = "/"
		}
		auth := ""
		if us := u.User; us != nil {
			auth = us.String() + "@"
		}
		return u.Scheme + "://" + auth + u.Host + path
	}
	return s
}

// ExpandMasqueHTTPSURI turns a path-only URI template into a full https URL by prefixing authority.
// If raw is empty, returns "". If raw starts with "/" (and not "//"), returns "https://"+httpsAuthority+raw.
// Otherwise returns raw trimmed (caller uses full https://… templates as today).
func ExpandMasqueHTTPSURI(raw string, httpsAuthority string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	auth := strings.TrimSpace(httpsAuthority)
	if strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "//") {
		return "https://" + auth + raw
	}
	return raw
}
