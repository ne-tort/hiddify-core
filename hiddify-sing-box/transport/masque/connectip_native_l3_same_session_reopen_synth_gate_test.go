package masque

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	mcip "github.com/sagernet/sing-box/transport/masque/connectip"
	ciptun "github.com/sagernet/sing-box/transport/masque/connectip/tun"
	msess "github.com/sagernet/sing-box/transport/masque/session"
	"github.com/yosida95/uritemplate/v3"
)

// TestGATEConnectIPNativeL3SameSessionReopenAfterUploadSynth mirrors Docker same-session recycle:
// native L3 bulk egress → server-recycle latch → ReopenConnectIPNativeL3Plane → ingress ready (TEST-2 synth).
func TestGATEConnectIPNativeL3SameSessionReopenAfterUploadSynth(t *testing.T) {
	t.Parallel()
	templateIP, err := uritemplate.New("https://example.com/masque/ip")
	if err != nil {
		t.Fatalf("build ip template: %v", err)
	}

	bulkPkt := []byte{0x45, 0x00, 0x00, 0x1c, 0, 0, 0x40, 0x00, 0x40, 0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	ingressCh := make(chan []byte, 128)
	reader := readPacketCtxAdapter{read: func(ctx context.Context, buf []byte) (int, error) {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case pkt := <-ingressCh:
			return copy(buf, pkt), nil
		}
	}}
	nat := ciptun.OverlayNAT{
		TunHost:   netip.MustParseAddr("198.18.0.2"),
		WireLocal: netip.MustParseAddr("198.18.0.1"),
	}
	bridge := ciptun.NewL3OverlayBridge(nil, stubNativeL3PacketWriter{}, reader, nat)
	bridge.SetStackIngressInject(func([]byte) error { return nil })
	plane := ciptun.NewNativeL3PlaneSession(bridge)

	var postReopenConn atomic.Pointer[connectip.Conn]
	cs := &coreSession{
		CoreSession: msess.CoreSession{
			Options:    ClientOptions{TransportMode: "connect_ip"},
			TemplateIP: templateIP,
			Caps:       CapabilitySet{ConnectIP: true},
			IPConn:     &connectip.Conn{},
		},
		dialConnectIPAttemptHook: func(context.Context, bool) (*connectip.Conn, error) {
			if c := postReopenConn.Load(); c != nil {
				return c, nil
			}
			return &connectip.Conn{}, nil
		},
	}
	cs.connectIPNativeL3Plane.Store(plane)
	cs.connectIPNativeL3Active.Store(true)
	cs.connectIPNativeL3EgressSess.Store(&l3BridgeEgressSession{bridge: bridge})
	plane.SetReadFatalHook(cs.noteConnectIPNativeL3IngressFatal)

	parentCtx, parentCancel := context.WithCancel(context.Background())
	defer parentCancel()
	plane.StartIngress(parentCtx)

	waitCtx, waitCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer waitCancel()
	if err := plane.WaitReady(waitCtx); err != nil {
		t.Fatalf("plane not ready: %v", err)
	}

	stopBulk := make(chan struct{})
	go func() {
		for {
			select {
			case <-stopBulk:
				return
			default:
				select {
				case ingressCh <- bulkPkt:
				default:
				}
			}
		}
	}()
	time.Sleep(40 * time.Millisecond)
	close(stopBulk)

	cs.MarkConnectIPServerRecycled()

	clientPipe, _ := newPacketPipePair()
	ps := mcip.ClientPacketSessionFromPipeShim(clientPipe)
	if ps == nil || ps.Conn() == nil {
		t.Fatal("pipe shim client session")
	}
	postReopenConn.Store(ps.Conn())

	reopenCtx, reopenCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer reopenCancel()
	if err := cs.ReopenConnectIPNativeL3Plane(reopenCtx); err != nil {
		t.Fatalf("ReopenConnectIPNativeL3Plane: %v", err)
	}
	if cs.ConnectIPServerGenerationStale() {
		t.Fatal("recycle latch must clear after successful same-session reopen")
	}
	if cs.IPConn != ps.Conn() {
		t.Fatal("expected reopened IPConn from dial hook")
	}

	readyCtx, readyCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer readyCancel()
	if err := plane.WaitReady(readyCtx); err != nil {
		t.Fatalf("plane not ready after reopen: %v", err)
	}

	select {
	case ingressCh <- bulkPkt:
	default:
		t.Fatal("ingress channel full before post-reopen read probe")
	}
}
