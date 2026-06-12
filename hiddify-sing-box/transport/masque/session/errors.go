package session

import (
	"errors"
	"net"
)

type ErrorClass string

const (
	ErrorClassUnknown      ErrorClass = "unknown"
	ErrorClassMisconfig    ErrorClass = "misconfig"
	ErrorClassCapability   ErrorClass = "capability"
	ErrorClassAuth         ErrorClass = "auth"
	ErrorClassLifecycle    ErrorClass = "lifecycle"
	ErrorClassTransport    ErrorClass = "transport_init"
	ErrorClassTCPStackInit ErrorClass = "tcp_stack_init"
	ErrorClassDial         ErrorClass = "tcp_dial"
	ErrorClassPolicy       ErrorClass = "policy"
)

var (
	ErrTCPPathNotImplemented  = errors.New("tcp path is not implemented for selected MASQUE transport")
	ErrTCPOverConnectIP       = errors.New("tcp over connect-ip path is not implemented yet")
	ErrUnsupportedNetwork     = errors.New("masque session unsupported network")
	ErrPolicyFallbackDenied   = errors.New("masque tcp fallback policy denied")
	ErrTCPConnectStreamFailed = errors.New("masque tcp connect-stream failed")

	// ErrConnectUDPTemplateNotConfigured is a configuration fault (missing CONNECT-UDP template).
	// Intentionally not prefixed with "masque h2:" so http_layer_fallback does not spend a pivot on it.
	ErrConnectUDPTemplateNotConfigured = errors.New("masque: CONNECT-UDP URI template is not configured")

	// ErrConnectIPTemplateNotConfigured is a configuration fault (missing CONNECT-IP template).
	// Same rationale as ErrConnectUDPTemplateNotConfigured: must not match "masque connect-ip h2:" handshake heuristics.
	ErrConnectIPTemplateNotConfigured = errors.New("masque: CONNECT-IP URI template is not configured")

	ErrMisconfig           = errors.New("masque misconfiguration")
	ErrCapability          = errors.New("masque capability mismatch")
	ErrTransportInit       = errors.New("masque transport init failed")
	ErrTCPStackInit        = errors.New("masque tcp stack init failed")
	ErrTCPDial             = errors.New("masque tcp dial failed")
	ErrFallbackExhausted   = errors.New("masque fallback exhausted")
	ErrDeadlineUnsupported = errors.New("masque stream deadline is unsupported")
	ErrAuthFailed          = errors.New("masque auth failed")
	ErrLifecycleClosed     = errors.New("masque lifecycle is closed")
)

func init() {
	SetDispatchErrors(DispatchErrors{
		UnsupportedNetwork:     ErrUnsupportedNetwork,
		AuthFailed:             ErrAuthFailed,
		LifecycleClosed:        ErrLifecycleClosed,
		TCPConnectStreamFailed: ErrTCPConnectStreamFailed,
		TCPDial:                ErrTCPDial,
	})
	SetDirectBackendErrors(DirectBackendErrors{
		TCPPathNotImplemented: ErrTCPPathNotImplemented,
		TCPOverConnectIP:      ErrTCPOverConnectIP,
		Capability:            ErrCapability,
	})
}

// ClassifyError maps masque sentinel errors to stable observability classes.
func ClassifyError(err error) ErrorClass {
	switch {
	case err == nil:
		return ErrorClassUnknown
	case errors.Is(err, ErrMisconfig):
		return ErrorClassMisconfig
	case errors.Is(err, ErrCapability), errors.Is(err, ErrTemplateCapability), errors.Is(err, ErrTCPPathNotImplemented), errors.Is(err, ErrTCPOverConnectIP), errors.Is(err, ErrUnsupportedNetwork):
		return ErrorClassCapability
	case errors.Is(err, ErrAuthFailed):
		return ErrorClassAuth
	case errors.Is(err, ErrLifecycleClosed):
		return ErrorClassLifecycle
	case errors.Is(err, ErrTransportInit):
		return ErrorClassTransport
	case errors.Is(err, ErrTCPStackInit):
		return ErrorClassTCPStackInit
	case errors.Is(err, ErrTCPDial), errors.Is(err, ErrTCPConnectStreamFailed):
		return ErrorClassDial
	case errors.Is(err, net.ErrClosed):
		return ErrorClassLifecycle
	case errors.Is(err, ErrPolicyFallbackDenied):
		return ErrorClassPolicy
	default:
		return ErrorClassUnknown
	}
}
