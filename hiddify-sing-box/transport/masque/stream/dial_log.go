package stream

import (
	"errors"
	"net"
	"strconv"
	"strings"
)

// ConnectStreamLogInput carries fields for masque_http_layer_chosen logging (no secrets).
type ConnectStreamLogInput struct {
	TCPURLHost      string
	Server          string
	ServerPort      uint16
	ResolveDialAddr func() string
}

// ConnectStreamChosenLogFields mirrors H2/H3 CONNECT-stream attempt logging so
// masque_http_layer_chosen stays aligned with masque_http_layer_attempt.
func ConnectStreamChosenLogFields(in ConnectStreamLogInput) (target, dial string) {
	target = strings.TrimSpace(in.TCPURLHost)
	if target == "" {
		port := int(in.ServerPort)
		if port <= 0 {
			port = 443
		}
		target = net.JoinHostPort(strings.TrimSpace(in.Server), strconv.Itoa(port))
	}
	if in.ResolveDialAddr != nil {
		dial = in.ResolveDialAddr()
	}
	return target, dial
}

// IsConnectStreamHTTP400 reports HTTP 400 CONNECT-stream failures used to auto-retry
// with bracketed IPv6 in the path when the first attempt used a bare literal.
func IsConnectStreamHTTP400(err error) bool {
	if err == nil || !errors.Is(err, Errs.TCPConnectStreamFailed) {
		return false
	}
	return strings.Contains(err.Error(), "status=400")
}
