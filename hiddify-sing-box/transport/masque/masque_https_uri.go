package masque

import (
	"net"
	"net/url"
	"strings"
)

// indexFold returns the index of substr in s with ASCII case folding for s only (substr is lower-case ASCII).
func indexFold(s, substr string) int {
	if substr == "" {
		return 0
	}
	outer := len(s) - len(substr)
	for i := 0; i <= outer; i++ {
		if matchFold(s[i:i+len(substr)], substr) {
			return i
		}
	}
	return -1
}

func matchFold(a, bLower string) bool {
	if len(a) != len(bLower) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], bLower[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// NormalizeMasqueTCPUDPTemplateTargetHost rewrites RFC 6570 simple `{target_host}` (and common
// modifiers) to reserved `{+target_host}` so IPv6 literals are not percent-encoded in the path.
// Percent-encoded colons (`2001%3A67c%3A...`) break many MASQUE reverse proxies (HTTP 502 on
// CONNECT-stream) that expect literal colons or bracketed IPv6 in the path segment.
func NormalizeMasqueTCPUDPTemplateTargetHost(raw string) string {
	if raw == "" || !strings.Contains(raw, "target_host") {
		return raw
	}
	s := raw
	// Longer / prefixed forms first; plain `{target_host}` must be last.
	s = strings.ReplaceAll(s, "{target_host*}", "{+target_host*}")
	s = strings.ReplaceAll(s, "{target_host:", "{+target_host:")
	s = strings.ReplaceAll(s, "{target_host}", "{+target_host}")
	return s
}

// MasqueTCPPathHostForTemplate returns the value used for `{+target_host}` when expanding
// template_tcp. IPv4 and hostnames are unchanged; when tcpIPv6PathBracket is true, IPv6 literals
// are RFC 5952-bracketed for path segments that confuse some reverse proxies when bare.
func MasqueTCPPathHostForTemplate(unbracketedHost string, tcpIPv6PathBracket bool) string {
	if !tcpIPv6PathBracket {
		return unbracketedHost
	}
	ip := net.ParseIP(strings.TrimSpace(unbracketedHost))
	if ip == nil || ip.To4() != nil {
		return unbracketedHost
	}
	return "[" + ip.String() + "]"
}

// MasqueTCPBracketRetryEligible reports whether the resolved TCP target host is a non‑IPv4 IP
// address suitable for an automatic CONNECT‑stream retry with bracketed IPv6 in the path
// (some reverse proxies return HTTP 400 for bare colons in `/tcp/…/`).
func MasqueTCPBracketRetryEligible(targetHost string) bool {
	ip := net.ParseIP(strings.TrimSpace(targetHost))
	return ip != nil && ip.To4() == nil
}

// FixMasqueExpandedTCPConnectStreamURL normalizes the host segment after "/tcp/" on the expanded
// template string before url.Parse: (1) percent-decodes IPv6 so the wire URL does not carry
// `%3A` (HTTP 502 on many MASQUE edges); (2) when tcpIPv6PathBracket is false, strips `[` `]`
// around a parseable IP (HTTP 400 on many edges for `/tcp/[2001::1]/…`); when true, keeps or
// inserts bracketed IPv6 for edges that reject unbracketed literals in the path.
func FixMasqueExpandedTCPConnectStreamURL(expanded string, tcpIPv6PathBracket bool) string {
	if expanded == "" {
		return expanded
	}
	const needle = "/tcp/"
	idx := indexFold(expanded, needle)
	if idx < 0 {
		return expanded
	}
	lo := idx + len(needle)
	if lo >= len(expanded) {
		return expanded
	}
	hi := strings.IndexByte(expanded[lo:], '/')
	if hi < 0 {
		return expanded
	}
	hi += lo
	hostSeg := expanded[lo:hi]

	bracketWire := func(literal string) string {
		ip := net.ParseIP(strings.TrimSpace(literal))
		if ip == nil || ip.To4() != nil {
			return literal
		}
		return "[" + ip.String() + "]"
	}

	if strings.Contains(hostSeg, "%") {
		dec, err := url.PathUnescape(hostSeg)
		if err != nil {
			return expanded
		}
		candidate := dec
		if len(dec) >= 2 && dec[0] == '[' && dec[len(dec)-1] == ']' {
			candidate = dec[1 : len(dec)-1]
		}
		if net.ParseIP(candidate) == nil {
			return expanded
		}
		seg := dec
		if len(dec) >= 2 && dec[0] == '[' && dec[len(dec)-1] == ']' {
			seg = candidate
		}
		if tcpIPv6PathBracket {
			seg = bracketWire(seg)
		}
		return expanded[:lo] + seg + expanded[hi:]
	}

	if len(hostSeg) >= 2 && hostSeg[0] == '[' && hostSeg[len(hostSeg)-1] == ']' {
		inner := hostSeg[1 : len(hostSeg)-1]
		if net.ParseIP(inner) != nil {
			if tcpIPv6PathBracket {
				return expanded[:lo] + bracketWire(inner) + expanded[hi:]
			}
			return expanded[:lo] + inner + expanded[hi:]
		}
	}
	if tcpIPv6PathBracket {
		if wire := bracketWire(hostSeg); wire != hostSeg {
			return expanded[:lo] + wire + expanded[hi:]
		}
	}
	return expanded
}

// RewriteMasqueTCPURLIfPercentEncodedIPv6 fixes CONNECT-stream request URLs where the TCP target host
// path segment is still percent-encoded (RFC 6570 simple `{target_host}` expansion, or legacy
// binaries). `net/url` keeps EscapedPath with `%3A`; many MASQUE edges return HTTP 502 for that wire
// form while accepting literal colons or bracketed IPv6 in the path segment.
//
// Templates shaped like `.../tcp/{host}/{port}` are detected by a path segment named `tcp`
// (case-insensitive); the following segment is treated as the host when PathUnescape yields a
// parseable IP address.
func RewriteMasqueTCPURLIfPercentEncodedIPv6(u *url.URL, tcpIPv6PathBracket bool) {
	if u == nil {
		return
	}
	bracketWire := func(literal string) string {
		ip := net.ParseIP(strings.TrimSpace(literal))
		if ip == nil || ip.To4() != nil {
			return literal
		}
		if tcpIPv6PathBracket {
			return "[" + ip.String() + "]"
		}
		return ip.String()
	}
	segs := strings.Split(strings.Trim(u.Path, "/"), "/")
	for i := 0; i+2 < len(segs); i++ {
		if !strings.EqualFold(segs[i], "tcp") {
			continue
		}
		hostSeg := segs[i+1]
		if len(hostSeg) >= 2 && hostSeg[0] == '[' && hostSeg[len(hostSeg)-1] == ']' {
			inner := hostSeg[1 : len(hostSeg)-1]
			if net.ParseIP(inner) != nil {
				segs[i+1] = bracketWire(inner)
				u.Path = "/" + strings.Join(segs, "/")
				u.RawPath = ""
				break
			}
		}
	}
	esc := u.EscapedPath()
	if !strings.Contains(esc, "%") {
		return
	}
	segs = strings.Split(strings.Trim(esc, "/"), "/")
	for i := 0; i+2 < len(segs); i++ {
		if !strings.EqualFold(segs[i], "tcp") {
			continue
		}
		hostSeg := segs[i+1]
		if !strings.Contains(hostSeg, "%") {
			continue
		}
		dec, err := url.PathUnescape(hostSeg)
		if err != nil {
			continue
		}
		candidate := dec
		if len(dec) >= 2 && dec[0] == '[' && dec[len(dec)-1] == ']' {
			candidate = dec[1 : len(dec)-1]
		}
		if net.ParseIP(candidate) == nil {
			continue
		}
		hostLiteral := dec
		if len(dec) >= 2 && dec[0] == '[' && dec[len(dec)-1] == ']' {
			hostLiteral = candidate
		}
		segs[i+1] = bracketWire(hostLiteral)
		u.Path = "/" + strings.Join(segs, "/")
		u.RawPath = ""
		return
	}
}

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
