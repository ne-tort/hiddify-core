package masque

import "strings"

// ExpandMasqueHTTPSURI turns a path-only URI template into a full https URL by prefixing authority.
// If raw is empty, returns "". If raw starts with "/" (and not "//"), returns "https://"+httpsAuthority+raw.
// Otherwise returns raw trimmed (caller uses full https://… templates as today).
//
// MASQUE libraries match :authority to the host part of this URL; authority must match the client
// server:port (client) or derived listen authority (server).
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
