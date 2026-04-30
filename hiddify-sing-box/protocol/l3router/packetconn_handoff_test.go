package l3routerendpoint

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	rt "github.com/sagernet/sing-box/common/l3router"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

type syntheticPacketConn struct {
	closed chan struct{}
}

func newSyntheticPacketConn() *syntheticPacketConn {
	return &syntheticPacketConn{closed: make(chan struct{})}
}

func (s *syntheticPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	<-s.closed
	return M.Socksaddr{}, net.ErrClosed
}

func (s *syntheticPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	return nil
}

func (s *syntheticPacketConn) Close() error {
	select {
	case <-s.closed:
	default:
		close(s.closed)
	}
	return nil
}

func (s *syntheticPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{}
}

func (s *syntheticPacketConn) SetDeadline(t time.Time) error {
	return nil
}

func (s *syntheticPacketConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (s *syntheticPacketConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func TestPacketConnHandoffRegistersAndCleansSession(t *testing.T) {
	ep := newEndpointForSurfaceTest(t)
	conn := newSyntheticPacketConn()
	md := adapter.InboundContext{User: "owner-a"}
	closed := make(chan error, 1)

	// synthetic early hook: router tracker phase before endpoint handler.
	ep.RoutedPacketConnection(context.Background(), conn, md, nil, ep)
	ep.NewPacketConnectionEx(context.Background(), conn, md, func(err error) {
		closed <- err
	})

	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		if ep.sessionConn(rt.SessionKey("owner-a")) != nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if ep.sessionConn(rt.SessionKey("owner-a")) == nil {
		t.Fatal("expected packet conn handoff to register writable session")
	}
	metrics := ep.SnapshotMetrics()
	if metrics.SessionReadyTransitions == 0 {
		t.Fatal("expected readiness transition after registerSession")
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("close synthetic conn: %v", err)
	}

	select {
	case err := <-closed:
		if err == nil {
			t.Fatal("expected onClose error after synthetic conn close")
		}
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("expected net.ErrClosed, got: %v", err)
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("timeout waiting onClose callback")
	}

	deadline = time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		if ep.sessionConn(rt.SessionKey("owner-a")) == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if ep.sessionConn(rt.SessionKey("owner-a")) != nil {
		t.Fatal("expected session conn cleanup after close")
	}
}

func TestEarlyHookOnlyDoesNotCreateWritableSession(t *testing.T) {
	ep := newEndpointForSurfaceTest(t)
	conn := newSyntheticPacketConn()
	md := adapter.InboundContext{User: "owner-a"}

	ep.RoutedPacketConnection(context.Background(), conn, md, nil, ep)

	if ep.sessionConn(rt.SessionKey("owner-a")) != nil {
		t.Fatal("tracker early hook must not create writable session without NewPacketConnectionEx")
	}
}

func TestRegisterSessionLastWinsIncrementsReplacementMetric(t *testing.T) {
	ep := newEndpointForSurfaceTest(t)
	md := adapter.InboundContext{User: "owner-a"}
	conn1 := newSyntheticPacketConn()
	conn2 := newSyntheticPacketConn()

	ep.NewPacketConnectionEx(context.Background(), conn1, md, nil)
	ep.NewPacketConnectionEx(context.Background(), conn2, md, nil)

	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		if ep.sessionConn(rt.SessionKey("owner-a")) == conn2 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if ep.sessionConn(rt.SessionKey("owner-a")) != conn2 {
		t.Fatal("expected newer session to replace old one (last-wins)")
	}
	metrics := ep.SnapshotMetrics()
	if metrics.SessionReplacements == 0 {
		t.Fatal("expected session replacement metric to increase")
	}
	_ = conn1.Close()
	_ = conn2.Close()
}
