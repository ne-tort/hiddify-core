package stream

import (
	"context"
	"errors"
	"net"
	"strings"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

const (
	// One transport-fault retry inside the outer handshake budget (dialTCPStream ctx).
	defaultConnectStreamDialMaxAttempts = 2
	defaultConnectStreamDialBackoffMs   = 200
)

// ConnectStreamDialMaxAttempts returns H3/H2 CONNECT-stream round-trip retry budget.
func ConnectStreamDialMaxAttempts() int {
	return defaultConnectStreamDialMaxAttempts
}

// ConnectStreamDialBackoff returns per-attempt delay before retrying a transport fault.
func ConnectStreamDialBackoff(attempt int) time.Duration {
	baseMs := defaultConnectStreamDialBackoffMs
	if attempt < 0 {
		attempt = 0
	}
	return time.Duration(attempt+1) * time.Duration(baseMs) * time.Millisecond
}

// TCPConnectStreamErrMayBenefitFromNextHop is true for overlay/network/handshake faults where
// advancing hopOrder might help. False for capability errors and exhausted dial budgets.
func TCPConnectStreamErrMayBenefitFromNextHop(err error) bool {
	if err == nil || errors.Is(err, Errs.Capability) {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	if IsLocalGracefulH3Close(err) {
		return false
	}
	return true
}

// connectStreamRoundTripShouldRetry: only confirmed transport death, not budget expiry.
func connectStreamRoundTripShouldRetry(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	if IsLocalGracefulH3Close(err) {
		return false
	}
	return IsRetryableTCPStreamError(err)
}

// IsRetryableTCPStreamError reports whether dialTCPStreamHTTP3/H2 may retry the round trip.
func IsRetryableTCPStreamError(err error) bool {
	return isRetryableTCPStreamErrorWalk(err)
}

// IsLocalGracefulH3Close reports locally initiated QUIC/H3 close-with-no-error.
// This should not trigger overlay-wide churn: it's often a byproduct of local
// lifecycle/teardown and can cascade browser traffic failures when treated as
// a global transport death signal.
func IsLocalGracefulH3Close(err error) bool {
	return isLocalGracefulH3CloseWalk(err)
}

func isLocalGracefulH3CloseWalk(err error) bool {
	if err == nil {
		return false
	}
	if isLocalGracefulH3CloseOne(err) {
		return true
	}
	type joinUnwrapper interface {
		Unwrap() []error
	}
	if u, ok := err.(joinUnwrapper); ok {
		for _, e := range u.Unwrap() {
			if isLocalGracefulH3CloseWalk(e) {
				return true
			}
		}
	}
	if u := errors.Unwrap(err); u != nil {
		return isLocalGracefulH3CloseWalk(u)
	}
	return false
}

func isLocalGracefulH3CloseOne(err error) bool {
	var h3Err *http3.Error
	if errors.As(err, &h3Err) {
		return !h3Err.Remote && h3Err.ErrorCode == 0
	}
	var appErr *quic.ApplicationError
	if errors.As(err, &appErr) {
		return !appErr.Remote && uint64(appErr.ErrorCode) == 0
	}
	return false
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
		if !appErr.Remote && uint64(appErr.ErrorCode) == 0 {
			return false
		}
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
