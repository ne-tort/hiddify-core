package masque

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

func ClassifyError(err error) ErrorClass {
	switch {
	case err == nil:
		return ErrorClassUnknown
	case errors.Is(err, ErrMisconfig):
		return ErrorClassMisconfig
	case errors.Is(err, ErrCapability), errors.Is(err, ErrTCPPathNotImplemented), errors.Is(err, ErrTCPOverConnectIP), errors.Is(err, ErrUnsupportedNetwork):
		return ErrorClassCapability
	case errors.Is(err, ErrAuthFailed):
		return ErrorClassAuth
	// Keep lifecycle classification deterministic when the caller explicitly closes the runtime.
	case errors.Is(err, ErrLifecycleClosed):
		return ErrorClassLifecycle
	case errors.Is(err, ErrTransportInit):
		return ErrorClassTransport
	case errors.Is(err, ErrTCPStackInit):
		return ErrorClassTCPStackInit
	case errors.Is(err, ErrTCPDial), errors.Is(err, ErrTCPConnectStreamFailed):
		return ErrorClassDial
	// net.ErrClosed is a broad sentinel that frequently appears as an unwrap cause for QUIC / H3 errors.
	// Prefer explicit masque sentinels (dial/transport/etc.) over a generic lifecycle classification.
	case errors.Is(err, net.ErrClosed):
		return ErrorClassLifecycle
	case errors.Is(err, ErrPolicyFallbackDenied):
		return ErrorClassPolicy
	default:
		return ErrorClassUnknown
	}
}
