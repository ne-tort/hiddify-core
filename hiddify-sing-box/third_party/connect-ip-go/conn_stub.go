package connectip

import "errors"

// ErrTransportUnset reports ReadPacket on a Conn without QUIC/stream/datagram wiring.
var ErrTransportUnset = errors.New("connect-ip: transport unset")

func (c *Conn) transportReady() bool {
	if c == nil {
		return false
	}
	return c.str != nil || c.datagramCapsuleIngress != nil || c.h3UnifiedDatagramIngress != nil
}

// NewStubIngressConn builds a capsule-ingress Conn for in-process unit tests (reuse/stale probe).
// ReadPacket blocks until ctx deadline when no datagram is queued.
func NewStubIngressConn() *Conn {
	c := &Conn{
		datagramCapsuleIngress: make(chan []byte, connReadPrefetchMax),
		closeChan:             make(chan struct{}),
		assignedAddressNotify: make(chan struct{}, 1),
		availableRoutesNotify: make(chan struct{}, 1),
		prefetchSlots:         make([][]byte, connReadPrefetchMax),
	}
	c.routeView.Store(&connRouteView{})
	return c
}
