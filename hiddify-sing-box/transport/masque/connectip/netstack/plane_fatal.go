package netstack

import (
	"context"
	"errors"
	"net"
	"strings"

	"github.com/quic-go/quic-go"
)

// IsConnectIPPlaneFatalForRecycle reports datagram-plane read/pump errors that indicate
// the remote masque-server generation is stale and the plane should reopen (LIFE-1).
// Benign half-close and transient retryable faults must not latch.
func IsConnectIPPlaneFatalForRecycle(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) {
		return false
	}

	// Structured server-generation stale signals (before benign half-close taxonomy).
	var resetErr *quic.StatelessResetError
	if errors.As(err, &resetErr) {
		return true
	}
	var idleErr *quic.IdleTimeoutError
	if errors.As(err, &idleErr) {
		return true
	}
	var appErr *quic.ApplicationError
	if errors.As(err, &appErr) {
		return appErr.Remote && appErr.ErrorCode != 0x100
	}

	if IsBenignEgressTeardownError(err) {
		return false
	}
	if IsRetryablePacketReadError(err) {
		return false
	}

	var transportErr *quic.TransportError
	if errors.As(err, &transportErr) {
		return transportErr.Remote
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Err != nil {
		s := strings.ToLower(opErr.Err.Error())
		if strings.Contains(s, "reset") ||
			strings.Contains(s, "refused") ||
			strings.Contains(s, "broken pipe") {
			return true
		}
	}

	text := strings.ToLower(err.Error())
	if strings.Contains(text, "stateless reset") || strings.Contains(text, "received a stateless reset") {
		return true
	}
	if strings.Contains(text, "connection reset") {
		return true
	}
	if strings.Contains(text, "peer going away") {
		return true
	}
	if strings.Contains(text, "application error") {
		return !strings.Contains(text, "0x100") && !strings.Contains(text, "0x0100")
	}
	return false
}
