package session

// CloseConnectUDPPlane tears down CONNECT-UDP QUIC/H2 transport while keeping the MASQUE session
// alive (LIFE-3 selector deselect). Mirrors CloseConnectIPPlane scope for the UDP plane only.
//
// Policy (AUDIT B14 / TASKS F3.2): close all live CONNECT-UDP PacketConns first, then drop
// UDPClient / H2UDPTransport. No silent orphans — mid-flight Read/Write unblock with closed errors.
func CloseConnectUDPPlane(s *CoreSession, host LifecycleHost) {
	host.CloseLiveConnectUDPPacketConns()
	s.Mu.Lock()
	host.CloseUDPClient()
	host.ResetH2UDPTransportLockedAssumeMu()
	s.Mu.Unlock()
}
