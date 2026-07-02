package masque

import (
	"context"
	"net/netip"
	"runtime"
	"testing"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/sagernet/sing-box/option"
	mcip "github.com/sagernet/sing-box/transport/masque/connectip"
	cipframe "github.com/sagernet/sing-box/transport/masque/connectip/frame"
	ciptun "github.com/sagernet/sing-box/transport/masque/connectip/tun"
	msess "github.com/sagernet/sing-box/transport/masque/session"
)

const (
	midBulkGoroutineSlack  = 8
	midBulkGoroutineSettle = 3 * time.Second
)

func goroutineBaseline() int {
	runtime.GC()
	time.Sleep(10 * time.Millisecond)
	return runtime.NumGoroutine()
}

func assertGoroutineSettle(t *testing.T, baseline, slack int) {
	t.Helper()
	deadline := time.Now().Add(midBulkGoroutineSettle)
	for time.Now().Before(deadline) {
		runtime.GC()
		if runtime.NumGoroutine() <= baseline+slack {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("goroutine leak: baseline=%d now=%d slack=%d", baseline, runtime.NumGoroutine(), slack)
}

// TestGATEConnectIPSessionCloseMidBulkNoLeak closes coreSession during active bulk ingress (LIFE-4).
func TestGATEConnectIPSessionCloseMidBulkNoLeak(t *testing.T) {
	t.Run("NativeL3", testGATENativeL3SessionCloseMidBulkNoLeak)
	t.Run("CMIngress", testGATECMIngressSessionCloseMidBulkNoLeak)
}

func testGATENativeL3SessionCloseMidBulkNoLeak(t *testing.T) {
	t.Parallel()
	bulkCh := make(chan []byte, 128)
	bulkPkt := []byte{0x45, 0x00, 0x00, 0x1c, 0, 0, 0x40, 0x00, 0x40, 0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	reader := readPacketCtxAdapter{read: func(ctx context.Context, buf []byte) (int, error) {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case pkt := <-bulkCh:
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

	cs := newTestCoreSession(msess.CoreSession{IPConn: &connectip.Conn{}})
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

	stopBulk := make(chan struct{})
	go func() {
		for {
			select {
			case <-stopBulk:
				return
			default:
				select {
				case bulkCh <- bulkPkt:
				default:
				}
			}
		}
	}()
	time.Sleep(30 * time.Millisecond)

	baseline := goroutineBaseline()
	if err := cs.Close(); err != nil {
		close(stopBulk)
		t.Fatalf("close: %v", err)
	}
	close(stopBulk)

	if !plane.IngressStopped() {
		t.Fatal("expected native L3 ingress stopped after session close")
	}
	if cs.connectIPNativeL3Plane.Load() != nil {
		t.Fatal("expected native L3 plane cleared")
	}
	assertGoroutineSettle(t, baseline, midBulkGoroutineSlack)
}

func testGATECMIngressSessionCloseMidBulkNoLeak(t *testing.T) {
	t.Parallel()
	clientPipe, _ := newPacketPipePair()
	ps := mcip.ClientPacketSessionFromPipeShim(clientPipe)
	if ps == nil || ps.Conn() == nil {
		t.Fatal("pipe shim client session")
	}
	bulkPkt, err := cipframe.BuildIPv4UDPPacket(
		netip.MustParseAddr("10.200.0.2"), 53,
		netip.MustParseAddr("198.18.0.2"), 53000,
		[]byte("bulk"),
	)
	if err != nil {
		t.Fatalf("build bulk pkt: %v", err)
	}

	cs := newTestCoreSession(msess.CoreSession{
		Options: ClientOptions{DataplaneMode: option.MasqueDataplaneConnectIP},
		Caps:    CapabilitySet{ConnectIP: true},
		IPConn:  ps.Conn(),
	})
	cs.ipIngressPacketReader.Store(ps)
	sub := cs.registerUDPIngressSubscriber()
	defer cs.unregisterUDPIngressSubscriber(sub)

	stopBulk := make(chan struct{})
	go func() {
		for {
			select {
			case <-stopBulk:
				return
			default:
				select {
				case clientPipe.sendCh <- bulkPkt:
				default:
				}
			}
		}
	}()
	time.Sleep(30 * time.Millisecond)

	baseline := goroutineBaseline()
	if err := cs.Close(); err != nil {
		close(stopBulk)
		t.Fatalf("close: %v", err)
	}
	close(stopBulk)

	if cs.connectIPIngressPlane().Running() {
		t.Fatal("expected CM ingress stopped after session close")
	}
	assertGoroutineSettle(t, baseline, midBulkGoroutineSlack)
}
