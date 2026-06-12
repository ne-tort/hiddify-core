package server

import (
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/quic-go/quic-go"
)

// TCPBindFailureRetryable matches OS-level bind denials where the kernel picked an ephemeral
// UDP port that cannot be shared with a collocated TCP listener (observed on Windows excluded ranges).
func TCPBindFailureRetryable(err error) bool {
	if err == nil {
		return false
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "forbidden") ||
		strings.Contains(text, "permission denied") ||
		strings.Contains(text, "access is denied") ||
		strings.Contains(text, "wsaeaccess")
}

// EphemeralDualBindTCPRetryable is used only when ListenPort==0: UDP may bind while the
// collocated TCP listener on the same ephemeral port is still in use (parallel tests, TIME_WAIT).
func EphemeralDualBindTCPRetryable(err error) bool {
	if TCPBindFailureRetryable(err) {
		return true
	}
	if err == nil {
		return false
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "address already in use") ||
		strings.Contains(text, "only one usage of each socket address") ||
		strings.Contains(text, "wsaeaddrinuse")
}

// ExpectedShutdownError reports whether err is a benign server shutdown race (Close vs Serve).
func ExpectedShutdownError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, http.ErrServerClosed) || errors.Is(err, quic.ErrServerClosed) {
		return true
	}
	text := strings.ToLower(strings.TrimSpace(err.Error()))
	return strings.Contains(text, "use of closed network connection") ||
		strings.Contains(text, "server closed")
}
