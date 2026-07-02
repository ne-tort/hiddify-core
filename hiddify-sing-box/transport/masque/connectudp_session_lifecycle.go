package masque

import (
	"github.com/sagernet/sing-box/transport/masque/session"
)

// CloseConnectUDPPlane tears down CONNECT-UDP packet plane while keeping the core session alive (LIFE-3).
func (s *coreSession) CloseConnectUDPPlane() {
	s.closeConnectUDPPlane()
}

func (s *coreSession) closeConnectUDPPlane() {
	session.CloseConnectUDPPlane(&s.CoreSession, s.lifecycleHost())
}
