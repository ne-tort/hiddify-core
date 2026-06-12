package masque

import "github.com/sagernet/sing-box/transport/masque/session"

// newTestCoreSession builds a coreSession for in-package tests (phase F session extract).
func newTestCoreSession(cs session.CoreSession) *coreSession {
	return &coreSession{CoreSession: cs}
}
