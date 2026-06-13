package masque

import (
	"github.com/sagernet/sing-box/transport/masque/session"
)

// ClassifyMalformedScopedTargetClassPair classifies malformed scoped CONNECT-IP options for runtime/transport parity gates.
func ClassifyMalformedScopedTargetClassPair(scopeTarget string) (session.ErrorClass, session.ErrorClass, error) {
	return session.ClassifyMalformedScopedTargetClassPair(session.ClientOptions{
		Server:               "example.com",
		ServerPort:           443,
		TemplateIP:           "https://example.com/masque/ip/{target}/{ipproto}",
		ConnectIPScopeTarget: scopeTarget,
	}, masqueTemplateHooks())
}
