package masque

import (
	"github.com/sagernet/sing-box/transport/masque/session"
)

type (
	ErrorClass          = session.ErrorClass
	ScopedErrorArtifact = session.ScopedErrorArtifact
)

const (
	ErrorClassUnknown      = session.ErrorClassUnknown
	ErrorClassMisconfig    = session.ErrorClassMisconfig
	ErrorClassCapability   = session.ErrorClassCapability
	ErrorClassAuth         = session.ErrorClassAuth
	ErrorClassLifecycle    = session.ErrorClassLifecycle
	ErrorClassTransport    = session.ErrorClassTransport
	ErrorClassTCPStackInit = session.ErrorClassTCPStackInit
	ErrorClassDial         = session.ErrorClassDial
	ErrorClassPolicy       = session.ErrorClassPolicy

	ErrorSourceRuntime   = session.ErrorSourceRuntime
	ErrorSourceComposeUp = session.ErrorSourceComposeUp
)

var (
	ErrTCPPathNotImplemented           = session.ErrTCPPathNotImplemented
	ErrTCPOverConnectIP                = session.ErrTCPOverConnectIP
	ErrUnsupportedNetwork              = session.ErrUnsupportedNetwork
	ErrPolicyFallbackDenied            = session.ErrPolicyFallbackDenied
	ErrTCPConnectStreamFailed          = session.ErrTCPConnectStreamFailed
	ErrConnectUDPTemplateNotConfigured = session.ErrConnectUDPTemplateNotConfigured
	ErrConnectIPTemplateNotConfigured  = session.ErrConnectIPTemplateNotConfigured
	ErrMisconfig                       = session.ErrMisconfig
	ErrCapability                      = session.ErrCapability
	ErrTransportInit                   = session.ErrTransportInit
	ErrTCPStackInit                    = session.ErrTCPStackInit
	ErrTCPDial                         = session.ErrTCPDial
	ErrFallbackExhausted               = session.ErrFallbackExhausted
	ErrDeadlineUnsupported             = session.ErrDeadlineUnsupported
	ErrAuthFailed                      = session.ErrAuthFailed
	ErrLifecycleClosed                 = session.ErrLifecycleClosed
)

func ClassifyError(err error) ErrorClass {
	return session.ClassifyError(err)
}

func BuildScopedErrorArtifact(actualClass, resultClass ErrorClass, source string) ScopedErrorArtifact {
	return session.BuildScopedErrorArtifact(actualClass, resultClass, source)
}

// ClassifyMalformedScopedTargetClassPair provides a shared typed source for malformed scoped parity tests.
func ClassifyMalformedScopedTargetClassPair(scopeTarget string) (actualClass ErrorClass, resultClass ErrorClass, err error) {
	return session.ClassifyMalformedScopedTargetClassPair(ClientOptions{
		Server:               "example.com",
		ServerPort:           443,
		TemplateIP:           "https://example.com/masque/ip/{target}/{ipproto}",
		ConnectIPScopeTarget: scopeTarget,
	}, masqueTemplateHooks())
}
