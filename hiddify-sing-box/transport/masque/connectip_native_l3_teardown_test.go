package masque

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	ciptun "github.com/sagernet/sing-box/transport/masque/connectip/tun"
	msess "github.com/sagernet/sing-box/transport/masque/session"
)

type stubNativeL3PacketWriter struct{}

func (stubNativeL3PacketWriter) WritePacket([]byte) ([]byte, error) { return nil, nil }

func TestStopConnectIPNativeL3DataplaneStopsPumpAndClearsState(t *testing.T) {
	block := make(chan struct{})
	reader := readPacketCtxAdapter{read: func(ctx context.Context, _ []byte) (int, error) {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-block:
			return 0, context.Canceled
		}
	}}
	nat := ciptun.OverlayNAT{
		TunHost:   netip.MustParseAddr("198.18.0.2"),
		WireLocal: netip.MustParseAddr("198.18.0.1"),
	}
	bridge := ciptun.NewL3OverlayBridge(nil, stubNativeL3PacketWriter{}, reader, nat)
	bridge.SetStackIngressInject(func([]byte) error { return nil })
	plane := ciptun.NewNativeL3PlaneSession(bridge)

	cs := newTestCoreSession(msess.CoreSession{IPConn: &connectip.Conn{}})
	cs.connectIPNativeL3Plane.Store(plane)
	cs.connectIPNativeL3Active.Store(true)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	plane.StartIngress(ctx)

	waitCtx, waitCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer waitCancel()
	if err := plane.WaitReady(waitCtx); err != nil {
		close(block)
		t.Fatalf("plane not ready: %v", err)
	}

	cs.stopConnectIPNativeL3Dataplane()

	if cs.connectIPNativeL3Plane.Load() != nil {
		t.Fatal("expected native l3 plane cleared")
	}
	if cs.ConnectIPNativeL3Active() {
		t.Fatal("expected native l3 inactive after stop")
	}
	if err := bridge.Send([]byte{0x45, 0x00}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected closed bridge send error, got: %v", err)
	}

	cs.stopConnectIPNativeL3Dataplane() // idempotent
}

func TestCoreSessionCloseStopsNativeL3BeforeSharedIPConn(t *testing.T) {
	sharedConn := &connectip.Conn{}
	reader := readPacketCtxAdapter{read: func(ctx context.Context, _ []byte) (int, error) {
		<-ctx.Done()
		return 0, ctx.Err()
	}}
	nat := ciptun.OverlayNAT{
		TunHost:   netip.MustParseAddr("198.18.0.2"),
		WireLocal: netip.MustParseAddr("198.18.0.1"),
	}
	bridge := ciptun.NewL3OverlayBridge(nil, stubNativeL3PacketWriter{}, reader, nat)
	bridge.SetStackIngressInject(func([]byte) error { return nil })
	plane := ciptun.NewNativeL3PlaneSession(bridge)

	cs := newTestCoreSession(msess.CoreSession{IPConn: sharedConn})
	cs.connectIPNativeL3Plane.Store(plane)
	cs.connectIPNativeL3Active.Store(true)

	pumpCtx, pumpCancel := context.WithCancel(context.Background())
	defer pumpCancel()
	plane.StartIngress(pumpCtx)

	waitCtx, waitCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer waitCancel()
	if err := plane.WaitReady(waitCtx); err != nil {
		t.Fatalf("plane not ready: %v", err)
	}

	// Close tears down native L3 first; IPConn may still be set until LifecycleClose unlock path.
	if err := cs.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if cs.ConnectIPNativeL3Active() {
		t.Fatal("expected native l3 inactive after session close")
	}
	if cs.connectIPNativeL3Plane.Load() != nil {
		t.Fatal("expected native l3 plane cleared after session close")
	}
	if cs.IPConn != nil {
		t.Fatal("expected shared ip conn cleared after session close")
	}
}

func TestStopConnectIPNativeL3DataplaneNoOpWhenUnwired(t *testing.T) {
	cs := newTestCoreSession(msess.CoreSession{})
	cs.stopConnectIPNativeL3Dataplane()
	cs.stopConnectIPNativeL3Dataplane()
}
