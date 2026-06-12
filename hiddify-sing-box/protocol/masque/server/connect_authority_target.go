package server

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
)

// ParseCONNECTAuthorityTarget returns onward TCP host/port from RFC 9114 CONNECT by authority.
func ParseCONNECTAuthorityTarget(r *http.Request) (host, port string, err error) {
	if r == nil {
		return "", "", E.New("nil request")
	}
	u := r.URL
	if u != nil && u.Host != "" {
		if u.Scheme != "" && u.Scheme != "https" && u.Scheme != "http" {
			return "", "", E.New("unsupported connect scheme")
		}
		return splitAuthorityHostPortDefault(u.Hostname(), u.Port(), u.Scheme == "https" || u.Scheme == "")
	}
	if h := strings.TrimSpace(r.Host); h != "" {
		return splitAuthorityHostPortDefault(authorityHostFromHostport(h), authorityPortFromHostport(h), true)
	}
	return "", "", E.New("missing connect authority target")
}

func authorityHostFromHostport(hostport string) string {
	h, _, err := net.SplitHostPort(strings.TrimSpace(hostport))
	if err != nil {
		return strings.Trim(strings.TrimSpace(hostport), "[]")
	}
	return strings.Trim(h, "[]")
}

func authorityPortFromHostport(hostport string) string {
	_, p, err := net.SplitHostPort(strings.TrimSpace(hostport))
	if err != nil {
		return ""
	}
	return p
}

func splitAuthorityHostPortDefault(host, port string, defaultHTTPS bool) (string, string, error) {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" {
		return "", "", fmt.Errorf("empty connect target host")
	}
	if port == "" {
		if defaultHTTPS {
			port = "443"
		} else {
			port = "80"
		}
	}
	return host, port, nil
}
