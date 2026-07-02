package session

// CloseConnectUDPPlane tears down CONNECT-UDP QUIC/H2 transport while keeping the MASQUE session
// alive (LIFE-3 selector deselect). Mirrors CloseConnectIPPlane scope for the UDP plane only.
func CloseConnectUDPPlane(s *CoreSession, host LifecycleHost) {
	s.Mu.Lock()
	host.CloseUDPClient()
	host.ResetH2UDPTransportLockedAssumeMu()
	s.Mu.Unlock()
}
