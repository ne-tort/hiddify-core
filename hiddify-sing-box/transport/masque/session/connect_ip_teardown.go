package session

// ConnectIPTeardownHost wires ingress hooks from package masque for CONNECT-IP dataplane teardown.
type ConnectIPTeardownHost interface {
	ClearPreTCPNetstackIngress()
	JoinConnectIPIngress()
	ClearIPIngressPacketReader()
}

// ConnectIPAbandonHost extends teardown with overlay reset after an abandoned openIPSessionLocked.
type ConnectIPAbandonHost interface {
	ConnectIPTeardownHost
	CancelConnectIPIngress()
	ResetIPH3TransportLockedAssumeMu()
	ResetH2UDPTransportLockedAssumeMu()
}

// CloseConnectIPDataplaneLockedAssumeMu tears down CONNECT-IP packet plane in lifecycle order
// (ipConn → join ingress → tcpNetstack). Caller must hold s.Mu.
func CloseConnectIPDataplaneLockedAssumeMu(s *CoreSession, host ConnectIPTeardownHost) {
	s.ConnectIPTCPInstallInflight.Store(0)
	host.ClearPreTCPNetstackIngress()
	s.IngressTCPNetstack.Store(nil)
	if s.IPConn != nil {
		_ = s.IPConn.Close()
		s.IPConn = nil
	}
	host.JoinConnectIPIngress()
	if s.TCPNetstack != nil {
		_ = s.TCPNetstack.Close()
		s.TCPNetstack = nil
	}
	host.ClearIPIngressPacketReader()
}

// ReleaseOpenedConnectIPSessionIfAbandoned tears down CONNECT-IP plane state when openIPSessionLocked
// succeeded but the caller must return an error before the consumer receives a net.PacketConn.
// Caller must not hold s.Mu.
func ReleaseOpenedConnectIPSessionIfAbandoned(s *CoreSession, host ConnectIPAbandonHost) {
	host.CancelConnectIPIngress()
	s.Mu.Lock()
	defer s.Mu.Unlock()
	CloseConnectIPDataplaneLockedAssumeMu(s, host)
	host.ResetIPH3TransportLockedAssumeMu()
	host.ResetH2UDPTransportLockedAssumeMu()
}
