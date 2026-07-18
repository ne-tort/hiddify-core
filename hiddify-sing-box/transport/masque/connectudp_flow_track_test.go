package masque

import (
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque/session"
)

type stubUDPPacketConn struct {
	closed bool
}

func (s *stubUDPPacketConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, net.ErrClosed }
func (s *stubUDPPacketConn) WriteTo([]byte, net.Addr) (int, error)  { return 0, net.ErrClosed }
func (s *stubUDPPacketConn) Close() error                           { s.closed = true; return nil }
func (s *stubUDPPacketConn) LocalAddr() net.Addr                    { return nil }
func (s *stubUDPPacketConn) SetDeadline(time.Time) error            { return nil }
func (s *stubUDPPacketConn) SetReadDeadline(time.Time) error        { return nil }
func (s *stubUDPPacketConn) SetWriteDeadline(time.Time) error       { return nil }

// TestCloseConnectUDPPlaneClosesTrackedFlows covers AUDIT B14 / TASKS F3.2.
func TestCloseConnectUDPPlaneClosesTrackedFlows(t *testing.T) {
	cs := newTestCoreSession(session.CoreSession{})
	stub := &stubUDPPacketConn{}
	pc := cs.trackUDPPacketConn(stub)
	if cs.liveUDPPacketConnCount() != 1 {
		t.Fatalf("tracked=%d want 1", cs.liveUDPPacketConnCount())
	}

	cs.CloseConnectUDPPlane()

	if !stub.closed {
		t.Fatal("expected underlying PacketConn.Close on plane deselect")
	}
	if cs.liveUDPPacketConnCount() != 0 {
		t.Fatalf("live flows after deselect=%d want 0", cs.liveUDPPacketConnCount())
	}
	_ = pc.Close() // idempotent
}
