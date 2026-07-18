package masque

import (
	"net"
	"sync"
)

// trackedUDPPacketConn registers live CONNECT-UDP flows so plane deselect can Close them (AUDIT B14).
type trackedUDPPacketConn struct {
	net.PacketConn
	s    *coreSession
	once sync.Once
}

func (c *trackedUDPPacketConn) Close() error {
	var err error
	c.once.Do(func() {
		c.s.untrackUDPPacketConn(c)
		err = c.PacketConn.Close()
	})
	return err
}

func (s *coreSession) trackUDPPacketConn(pc net.PacketConn) net.PacketConn {
	if s == nil || pc == nil {
		return pc
	}
	t := &trackedUDPPacketConn{PacketConn: pc, s: s}
	s.udpFlowMu.Lock()
	if s.udpFlows == nil {
		s.udpFlows = make(map[*trackedUDPPacketConn]struct{})
	}
	s.udpFlows[t] = struct{}{}
	s.udpFlowMu.Unlock()
	return t
}

func (s *coreSession) untrackUDPPacketConn(c *trackedUDPPacketConn) {
	if s == nil || c == nil {
		return
	}
	s.udpFlowMu.Lock()
	delete(s.udpFlows, c)
	s.udpFlowMu.Unlock()
}

func (s *coreSession) closeLiveUDPPacketConns() {
	if s == nil {
		return
	}
	s.udpFlowMu.Lock()
	flows := make([]*trackedUDPPacketConn, 0, len(s.udpFlows))
	for f := range s.udpFlows {
		flows = append(flows, f)
	}
	s.udpFlowMu.Unlock()
	for _, f := range flows {
		_ = f.Close()
	}
}

func (s *coreSession) liveUDPPacketConnCount() int {
	if s == nil {
		return 0
	}
	s.udpFlowMu.Lock()
	n := len(s.udpFlows)
	s.udpFlowMu.Unlock()
	return n
}
