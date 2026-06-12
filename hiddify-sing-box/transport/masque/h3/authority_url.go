package h3

import (
	"net"
	"net/url"
	"strconv"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
)

// ExpandAuthorityConnectURL builds the CONNECT request URL (https://target:port/ by default).
func ExpandAuthorityConnectURL(templateConnect, targetHost string, targetPort uint16) (*url.URL, error) {
	host := strings.Trim(strings.TrimSpace(targetHost), "[]")
	if host == "" {
		return nil, E.New("empty target host")
	}
	port := int(targetPort)
	if port <= 0 || port > 65535 {
		return nil, E.New("invalid target port")
	}
	raw := strings.TrimSpace(templateConnect)
	if raw == "" {
		return &url.URL{Scheme: "https", Host: net.JoinHostPort(host, strconv.Itoa(port)), Path: "/"}, nil
	}
	expanded := strings.ReplaceAll(raw, "{target_host}", host)
	expanded = strings.ReplaceAll(expanded, "{target_port}", strconv.Itoa(port))
	expanded = strings.ReplaceAll(expanded, "{+target_host}", host)
	expanded = strings.ReplaceAll(expanded, "{+target_port}", strconv.Itoa(port))
	if !strings.Contains(expanded, "://") {
		expanded = "https://" + strings.TrimPrefix(expanded, "/")
	}
	u, err := url.Parse(expanded)
	if err != nil {
		return nil, E.Cause(err, "invalid template_connect")
	}
	if u.Scheme == "" {
		u.Scheme = "https"
	}
	if u.Host == "" {
		u.Host = net.JoinHostPort(host, strconv.Itoa(port))
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return u, nil
}
