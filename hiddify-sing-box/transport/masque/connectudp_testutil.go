package masque

import "context"

// ConnectUDPTestFactory is the exported session factory for connectudp integration tests.
type ConnectUDPTestFactory = CoreClientFactory

// NewConnectUDPTestSession builds a core MASQUE client session for CONNECT-UDP gate/localize tests.
func NewConnectUDPTestSession(ctx context.Context, opts ClientOptions) (ClientSession, error) {
	return (CoreClientFactory{}).NewSession(ctx, opts)
}

// ResetConnectUDPH2TransportForTest closes the cached CONNECT-UDP H2 http2.Transport on a session.
// Synth tests reuse CoreClientFactory sessions in-process; reset avoids stale pooled conns between cases.
func ResetConnectUDPH2TransportForTest(sess ClientSession) {
	s, ok := sess.(*coreSession)
	if !ok || s == nil {
		return
	}
	s.Mu.Lock()
	s.resetH2UDPTransportLockedAssumeMu()
	s.Mu.Unlock()
}

// closeConnectUDPTestSession closes a synth session and resets H2 transport cache when applicable.
func closeConnectUDPTestSession(sess ClientSession) {
	if sess == nil {
		return
	}
	_ = sess.Close()
	ResetConnectUDPH2TransportForTest(sess)
}
