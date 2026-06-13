package server

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	fwd "github.com/sagernet/sing-box/transport/masque/forwarder"
)

type stallPacketPlaneConn struct {
	readBlock chan struct{}
	closed    chan struct{}
}

func (c *stallPacketPlaneConn) ReadPacket([]byte) (int, error) {
	select {
	case <-c.readBlock:
		return 0, io.EOF
	case <-c.closed:
		return 0, net.ErrClosed
	}
}

func (c *stallPacketPlaneConn) WritePacket([]byte) ([]byte, error) { return nil, nil }
func (c *stallPacketPlaneConn) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return nil
}

func (c *stallPacketPlaneConn) CurrentPeerPrefixes() []netip.Prefix { return nil }

var _ fwd.PacketPlaneConn = (*stallPacketPlaneConn)(nil)

func TestConnectIPRouteActiveTracksBlockedRoute(t *testing.T) {
	t.Parallel()
	stall := &stallPacketPlaneConn{
		readBlock: make(chan struct{}),
		closed:    make(chan struct{}),
	}
	packetConn := NewConnectIPNetPacketConn(stall)

	routeCtx, routeCancel := context.WithCancel(context.Background())
	routeDone := make(chan struct{})
	go func() {
		defer close(routeDone)
		RouteConnectIPBlocked(nil, routeCtx, packetConn, adapter.InboundContext{}, nil, option.MasqueEndpointOptions{}, net.Dialer{})
	}()

	waitRouteActive := func() {
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			if ConnectIPRouteActiveCount() > 0 {
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
		t.Fatal("expected active connect-ip route")
	}
	waitRouteActive()

	if waitConnectIPRoutesDrained(50 * time.Millisecond) {
		t.Fatal("route still active; drain must not succeed early")
	}

	close(stall.readBlock)
	routeCancel()
	select {
	case <-routeDone:
	case <-time.After(3 * time.Second):
		t.Fatal("route did not exit after unblock")
	}
	if !waitConnectIPRoutesDrained(2 * time.Second) {
		t.Fatalf("route count=%d want 0 after handler exit", ConnectIPRouteActiveCount())
	}
}

func TestShutdownMasqueEndpointWaitsForConnectIPRouteDrain(t *testing.T) {
	t.Parallel()
	stall := &stallPacketPlaneConn{
		readBlock: make(chan struct{}),
		closed:    make(chan struct{}),
	}
	packetConn := NewConnectIPNetPacketConn(stall)

	routeCtx := context.Background()
	var routeWG sync.WaitGroup
	routeWG.Add(1)
	go func() {
		defer routeWG.Done()
		RouteConnectIPBlocked(nil, routeCtx, packetConn, adapter.InboundContext{}, nil, option.MasqueEndpointOptions{}, net.Dialer{})
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ConnectIPRouteActiveCount() > 0 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if ConnectIPRouteActiveCount() == 0 {
		t.Fatal("expected active route before shutdown drain test")
	}

	start := time.Now()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	stack := &MasqueStack{PacketConn: pc}
	if err := ShutdownMasqueEndpoint(ShutdownMasqueEndpointConfig{
		Stack:           stack,
		ShutdownTimeout: 4 * time.Second,
	}); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	elapsed := time.Since(start)
	if elapsed < 500*time.Millisecond {
		t.Fatalf("shutdown returned in %v without waiting for route drain", elapsed)
	}

	close(stall.readBlock)
	routeWG.Wait()
}
