package masque

import (
	"github.com/sagernet/sing-box/transport/masque/session"
)

// ClassifyMalformedScopedTargetClassPair classifies malformed scoped CONNECT-IP options for runtime/transport parity gates.
func ClassifyMalformedScopedTargetClassPair(scopeTarget string) (session.ErrorClass, session.ErrorClass, error) {
	return session.ClassifyMalformedScopedTargetClassPair(session.ClientOptions{
		Server:               "example.com",
		ServerPort:           443,
		PathIP:               "/.well-known/masque/ip",
		ConnectIPScopeTarget: scopeTarget,
	}, masqueTemplateHooks())
}
