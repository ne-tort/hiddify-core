package masque

import (
	connectip "github.com/quic-go/connect-ip-go"
	"github.com/sagernet/sing-box/transport/masque/session"
)

// newTestCoreSession builds a coreSession for in-package tests (phase F session extract).
func newTestCoreSession(cs session.CoreSession) *coreSession {
	return &coreSession{CoreSession: cs}
}

// testStubConnectIPConn returns a probe-safe CONNECT-IP conn for reuse/stale unit tests.
func testStubConnectIPConn() *connectip.Conn {
	return connectip.NewStubIngressConn()
}
