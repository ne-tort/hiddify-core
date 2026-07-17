package pathbuild

import (
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
)

// IANA / draft-ietf-httpbis-connect-tcp default path prefixes (no trailing slash).
const (
	DefaultPathUDP = "/.well-known/masque/udp"
	DefaultPathTCP = "/.well-known/masque/tcp"
	DefaultPathIP  = "/.well-known/masque/ip"
)

// Plane identifies which MASQUE URI family is being built.
type Plane string

const (
	PlaneUDP Plane = "udp"
	PlaneTCP Plane = "tcp"
	PlaneIP  Plane = "ip"
)

// ValidatePathPrefix checks a user path_* override (fixed prefix only).
func ValidatePathPrefix(raw string) error {
	p := strings.TrimSpace(raw)
	if p == "" {
		return nil
	}
	if !strings.HasPrefix(p, "/") {
		return E.New("masque path_* must start with /")
	}
	if strings.ContainsAny(p, "{}?#") {
		return E.New("masque path_* must be a fixed prefix without { } ? #")
	}
	if strings.Contains(p, "//") {
		return E.New("masque path_* must not contain //")
	}
	return nil
}

// ResolvePrefix returns the configured or default well-known prefix (no trailing slash).
func ResolvePrefix(plane Plane, configured string) string {
	p := strings.TrimSpace(configured)
	if p == "" {
		switch plane {
		case PlaneUDP:
			return DefaultPathUDP
		case PlaneTCP:
			return DefaultPathTCP
		case PlaneIP:
			return DefaultPathIP
		default:
			return ""
		}
	}
	return strings.TrimRight(p, "/")
}

// ValidateEndpointPaths validates path_* prefixes (obfuscation is a plain bool — no key to validate).
func ValidateEndpointPaths(pathUDP, pathTCP, pathIP string, _ bool) error {
	if err := ValidatePathPrefix(pathUDP); err != nil {
		return E.Cause(err, "path_udp")
	}
	if err := ValidatePathPrefix(pathTCP); err != nil {
		return E.Cause(err, "path_tcp")
	}
	if err := ValidatePathPrefix(pathIP); err != nil {
		return E.Cause(err, "path_ip")
	}
	u := ResolvePrefix(PlaneUDP, pathUDP)
	t := ResolvePrefix(PlaneTCP, pathTCP)
	i := ResolvePrefix(PlaneIP, pathIP)
	if u == t || u == i || t == i {
		return E.New("masque path_udp/path_tcp/path_ip prefixes must be unique")
	}
	return nil
}
