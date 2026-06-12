package stream

import (
	"errors"
	"net"
	"strings"
	"syscall"

	"github.com/quic-go/quic-go"
	"golang.org/x/net/http2"
)

// TCPConnectStreamErrMayBenefitFromNextHop is true for overlay/network/handshake faults where
// advancing hopOrder might help. False for capability errors (invalid Socksaddr, template expand).
func TCPConnectStreamErrMayBenefitFromNextHop(err error) bool {
	return err != nil && !errors.Is(err, Errs.Capability)
}

// IsRetryableTCPStreamError reports whether dialTCPStreamHTTP3/H2 may retry the round trip.
func IsRetryableTCPStreamError(err error) bool {
	if err == nil {
		return false
	}
	var appErr *quic.ApplicationError
	if errors.As(err, &appErr) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	var hsTimeout *quic.HandshakeTimeoutError
	if errors.As(err, &hsTimeout) {
		return true
	}
	if errors.Is(err, net.ErrClosed) {
		return false
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if opErr.Timeout() {
			return true
		}
		if opErr.Err != nil {
			var errno syscall.Errno
			if errors.As(opErr.Err, &errno) {
				switch errno {
				case syscall.ECONNRESET, syscall.ECONNREFUSED, syscall.ECONNABORTED, syscall.ETIMEDOUT, syscall.EPIPE:
					return true
				}
			}
		}
	}
	var h2cerr http2.ConnectionError
	if errors.As(err, &h2cerr) {
		return true
	}
	es := strings.ToLower(err.Error())
	switch {
	case strings.Contains(es, "broken pipe"),
		strings.Contains(es, "connection reset"),
		strings.Contains(es, "connection aborted"),
		strings.Contains(es, "tls:") && strings.Contains(es, "handshake"):
		return true
	default:
		return false
	}
}
