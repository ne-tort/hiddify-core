package session

import (
	"context"
	"errors"
	"fmt"
	"net"
)

// DispatchErrors holds sentinel errors for session dispatch and direct-TCP fallback policy.
// transport/masque wires these via SetDispatchErrors during init.
type DispatchErrors struct {
	UnsupportedNetwork      error
	AuthFailed              error
	LifecycleClosed         error
	TCPConnectStreamFailed  error
	TCPDial                 error
}

var defaultDispatchErrors = DispatchErrors{
	UnsupportedNetwork:     errors.New("session: unsupported network"),
	AuthFailed:             errors.New("session: auth failed"),
	LifecycleClosed:        errors.New("session: lifecycle closed"),
	TCPConnectStreamFailed: errors.New("session: tcp connect-stream failed"),
	TCPDial:                errors.New("session: tcp dial failed"),
}

// DispatchErrs holds package-level dispatch error sentinels.
var DispatchErrs = defaultDispatchErrors

// SetDispatchErrors installs dispatch error sentinels (called from transport/masque init).
func SetDispatchErrors(e DispatchErrors) {
	if e.UnsupportedNetwork != nil {
		DispatchErrs.UnsupportedNetwork = e.UnsupportedNetwork
	}
	if e.AuthFailed != nil {
		DispatchErrs.AuthFailed = e.AuthFailed
	}
	if e.LifecycleClosed != nil {
		DispatchErrs.LifecycleClosed = e.LifecycleClosed
	}
	if e.TCPConnectStreamFailed != nil {
		DispatchErrs.TCPConnectStreamFailed = e.TCPConnectStreamFailed
	}
	if e.TCPDial != nil {
		DispatchErrs.TCPDial = e.TCPDial
	}
}

// UnsupportedNetworkError reports a non-TCP dial family at the session dispatch boundary.
func UnsupportedNetworkError(network string) error {
	return errors.Join(DispatchErrs.UnsupportedNetwork, fmt.Errorf("unsupported network in masque session: %s", network))
}

// DirectBackendErrors holds sentinel errors for the plain-TCP direct backend session.
type DirectBackendErrors struct {
	TCPPathNotImplemented error
	TCPOverConnectIP      error
	Capability            error
}

var defaultDirectBackendErrors = DirectBackendErrors{
	TCPPathNotImplemented: errors.New("session: tcp path not implemented"),
	TCPOverConnectIP:      errors.New("session: tcp over connect-ip not implemented"),
	Capability:            errors.New("session: capability mismatch"),
}

// DirectBackendErrs holds package-level direct-backend error sentinels.
var DirectBackendErrs = defaultDirectBackendErrors

// SetDirectBackendErrors installs direct-backend error sentinels (called from transport/masque init).
func SetDirectBackendErrors(e DirectBackendErrors) {
	if e.TCPPathNotImplemented != nil {
		DirectBackendErrs.TCPPathNotImplemented = e.TCPPathNotImplemented
	}
	if e.TCPOverConnectIP != nil {
		DirectBackendErrs.TCPOverConnectIP = e.TCPOverConnectIP
	}
	if e.Capability != nil {
		DirectBackendErrs.Capability = e.Capability
	}
}

// TCPMasqueDirectFallbackEligible limits direct TCP fallback to CONNECT-stream failures after an
// explicit MasqueTCPModeMasqueOrDirect + MasqueFallbackPolicyDirectExplicit profile (validated in endpoint).
func TCPMasqueDirectFallbackEligible(err error, ctx context.Context) bool {
	if err == nil || ctx.Err() != nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	if errors.Is(err, DispatchErrs.AuthFailed) || errors.Is(err, DispatchErrs.LifecycleClosed) || errors.Is(err, net.ErrClosed) {
		return false
	}
	return errors.Is(err, DispatchErrs.TCPConnectStreamFailed) || errors.Is(err, DispatchErrs.TCPDial)
}
