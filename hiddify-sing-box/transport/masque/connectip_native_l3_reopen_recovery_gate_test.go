package masque

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/sagernet/sing-box/option"
	ciptun "github.com/sagernet/sing-box/transport/masque/connectip/tun"
	msess "github.com/sagernet/sing-box/transport/masque/session"
	"github.com/yosida95/uritemplate/v3"
)

// TestGATEConnectIPNativeL3ReopenOpenFailureRecovery ensures failed ReopenConnectIPNativeL3Plane
// does not leave native L3 ingress permanently stopped (LIFE-2).
func TestGATEConnectIPNativeL3ReopenOpenFailureRecovery(t *testing.T) {
	t.Parallel()
	templateIP, err := uritemplate.New("https://example.com/masque/ip")
	if err != nil {
		t.Fatalf("build ip template: %v", err)
	}

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

	cs := &coreSession{
		CoreSession: msess.CoreSession{
			Options:    ClientOptions{DataplaneMode: option.MasqueDataplaneConnectIP},
			TemplateIP: templateIP,
			Caps:       CapabilitySet{ConnectIP: true},
			IPConn:     &connectip.Conn{},
		},
		dialConnectIPAttemptHook: func(context.Context, bool) (*connectip.Conn, error) {
			return nil, errors.New("synth reopen open failed")
		},
	}
	cs.connectIPNativeL3Plane.Store(plane)
	cs.connectIPNativeL3Active.Store(true)
	cs.connectIPNativeL3EgressSess.Store(&l3BridgeEgressSession{bridge: bridge})
	cs.MarkConnectIPServerRecycled()

	parentCtx, parentCancel := context.WithCancel(context.Background())
	defer parentCancel()
	plane.StartIngress(parentCtx)

	waitCtx, waitCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer waitCancel()
	if err := plane.WaitReady(waitCtx); err != nil {
		close(block)
		t.Fatalf("plane not ready before reopen: %v", err)
	}

	reopenErr := cs.ReopenConnectIPNativeL3Plane(context.Background())
	if reopenErr == nil {
		t.Fatal("expected reopen error when OpenIPSession fails")
	}
	if !cs.ConnectIPServerGenerationStale() {
		t.Fatal("recycle latch must stay set after failed reopen")
	}

	recoverCtx, recoverCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer recoverCancel()
	if err := plane.WaitReady(recoverCtx); err != nil {
		t.Fatalf("ingress must restart after failed reopen, got: %v", err)
	}

	var dials atomic.Int32
	okConn := &connectip.Conn{}
	cs.dialConnectIPAttemptHook = func(context.Context, bool) (*connectip.Conn, error) {
		dials.Add(1)
		return okConn, nil
	}
	if err := cs.ReopenConnectIPNativeL3Plane(context.Background()); err != nil {
		t.Fatalf("successful reopen after recovery: %v", err)
	}
	if dials.Load() != 1 {
		t.Fatalf("expected one dial on successful reopen, got %d", dials.Load())
	}
	if cs.ConnectIPServerGenerationStale() {
		t.Fatal("recycle latch must clear after successful reopen")
	}
	if cs.IPConn != okConn {
		t.Fatal("expected reopened IPConn wired after successful reopen")
	}
	successCtx, successCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer successCancel()
	if err := plane.WaitReady(successCtx); err != nil {
		t.Fatalf("plane not ready after successful reopen: %v", err)
	}
}
