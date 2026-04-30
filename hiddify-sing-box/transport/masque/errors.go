package masque

import "errors"

type ErrorClass string

const (
	ErrorClassUnknown      ErrorClass = "unknown"
	ErrorClassMisconfig    ErrorClass = "misconfig"
	ErrorClassCapability   ErrorClass = "capability"
	ErrorClassAuth         ErrorClass = "auth"
	ErrorClassTransport    ErrorClass = "transport_init"
	ErrorClassTCPStackInit ErrorClass = "tcp_stack_init"
	ErrorClassDial         ErrorClass = "tcp_dial"
	ErrorClassPolicy       ErrorClass = "policy"
)

var (
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
	case errors.Is(err, ErrCapability), errors.Is(err, ErrTCPPathNotImplemented), errors.Is(err, ErrTCPOverConnectIP):
		return ErrorClassCapability
	case errors.Is(err, ErrAuthFailed):
		return ErrorClassAuth
	case errors.Is(err, ErrTransportInit):
		return ErrorClassTransport
	case errors.Is(err, ErrTCPStackInit):
		return ErrorClassTCPStackInit
	case errors.Is(err, ErrTCPDial), errors.Is(err, ErrTCPConnectStreamFailed):
		return ErrorClassDial
	case errors.Is(err, ErrPolicyFallbackDenied):
		return ErrorClassPolicy
	default:
		return ErrorClassUnknown
	}
}
