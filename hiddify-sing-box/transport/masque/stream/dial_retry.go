package stream

import (
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
	"golang.org/x/net/http2"
)

const (
	// Field/VPS bench parity (REF1-2): 5×200ms tolerates flaky remote QUIC without env.
	defaultConnectStreamDialMaxAttempts = 5
	defaultConnectStreamDialBackoffMs   = 200
	maxConnectStreamDialMaxAttempts     = 8
)

// ConnectStreamDialMaxAttempts returns H3/H2 CONNECT-stream round-trip retry budget.
// Field paths may raise via MASQUE_CONNECT_STREAM_DIAL_MAX_ATTEMPTS (default 3).
func ConnectStreamDialMaxAttempts() int {
	raw := strings.TrimSpace(os.Getenv("MASQUE_CONNECT_STREAM_DIAL_MAX_ATTEMPTS"))
	if raw == "" {
		return defaultConnectStreamDialMaxAttempts
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		return defaultConnectStreamDialMaxAttempts
	}
	if n > maxConnectStreamDialMaxAttempts {
		return maxConnectStreamDialMaxAttempts
	}
	return n
}

// ConnectStreamDialBackoff returns per-attempt delay before retrying a transport fault.
// MASQUE_CONNECT_STREAM_DIAL_BACKOFF_MS sets the base step (default 50ms; attempt n waits n×base).
func ConnectStreamDialBackoff(attempt int) time.Duration {
	baseMs := defaultConnectStreamDialBackoffMs
	raw := strings.TrimSpace(os.Getenv("MASQUE_CONNECT_STREAM_DIAL_BACKOFF_MS"))
	if raw != "" {
		if ms, err := strconv.Atoi(raw); err == nil && ms > 0 {
			baseMs = ms
		}
	}
	if attempt < 0 {
		attempt = 0
	}
	return time.Duration(attempt+1) * time.Duration(baseMs) * time.Millisecond
}

// TCPConnectStreamErrMayBenefitFromNextHop is true for overlay/network/handshake faults where
// advancing hopOrder might help. False for capability errors (invalid Socksaddr, template expand).
func TCPConnectStreamErrMayBenefitFromNextHop(err error) bool {
	return err != nil && !errors.Is(err, Errs.Capability)
}

// IsRetryableTCPStreamError reports whether dialTCPStreamHTTP3/H2 may retry the round trip.
func IsRetryableTCPStreamError(err error) bool {
	return isRetryableTCPStreamErrorWalk(err)
}

func isRetryableTCPStreamErrorWalk(err error) bool {
	if err == nil {
		return false
	}
	if isRetryableTCPStreamErrorOne(err) {
		return true
	}
	type joinUnwrapper interface {
		Unwrap() []error
	}
	if u, ok := err.(joinUnwrapper); ok {
		for _, e := range u.Unwrap() {
			if isRetryableTCPStreamErrorWalk(e) {
				return true
			}
		}
	}
	if u := errors.Unwrap(err); u != nil {
		return isRetryableTCPStreamErrorWalk(u)
	}
	return false
}

func isRetryableTCPStreamErrorOne(err error) bool {
	var appErr *quic.ApplicationError
	if errors.As(err, &appErr) {
		return true
	}
	var idleErr *quic.IdleTimeoutError
	if errors.As(err, &idleErr) {
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
		strings.Contains(es, "no recent network activity"),
		strings.Contains(es, "transport is closed"),
		strings.Contains(es, "tls:") && strings.Contains(es, "handshake"):
		return true
	default:
		return false
	}
}
