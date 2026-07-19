package ingress

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	cipframe "github.com/sagernet/sing-box/transport/masque/connectip/frame"
)

type symmetricPumpTestHost struct {
	readerCalls atomic.Int32
	flushAck    atomic.Int32
	pktCh       chan []byte
}

func (h *symmetricPumpTestHost) IngressTransportModeOK() bool { return true }
func (h *symmetricPumpTestHost) IngressPacketReader() func(context.Context, []byte) (int, error) {
	return func(ctx context.Context, buf []byte) (int, error) {
		h.readerCalls.Add(1)
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case pkt, ok := <-h.pktCh:
			if !ok {
				return 0, ctx.Err()
			}
			return copy(buf, pkt), nil
		}
	}
}
func (h *symmetricPumpTestHost) IngressTCPInstallInflight() bool        { return false }
func (h *symmetricPumpTestHost) IngressTCPNetstack() Netstack           { return nil }
func (h *symmetricPumpTestHost) IngressTCPNetstackForInject() Netstack  { return nil }
func (h *symmetricPumpTestHost) IngressTCPFastPath([]byte) bool         { return false }
func (h *symmetricPumpTestHost) IngressDeliverTCPNoFlush([]byte) bool  { return false }
func (h *symmetricPumpTestHost) IngressFlushAckWake()                  { h.flushAck.Add(1) }
func (h *symmetricPumpTestHost) IngressFlushEgressBatch()              {}
func (h *symmetricPumpTestHost) IngressWritePacket() func([]byte) ([]byte, error) {
	return func([]byte) ([]byte, error) { return nil, nil }
}
func (h *symmetricPumpTestHost) IngressOnReadFatal(error)                 {}
func (h *symmetricPumpTestHost) IngressDebugLog([]byte, int, bool, bool) {}
func (h *symmetricPumpTestHost) IngressObsEvent(string)                   {}
func (h *symmetricPumpTestHost) IngressEngineDrop(string)                 {}
func (h *symmetricPumpTestHost) IngressReadDrop(string)                   {}
func (h *symmetricPumpTestHost) IngressSessionReset(string)               {}

// TestIngressMaybeStartUsesSymmetricRunTunnel verifies U0-5: CM ingress runs RunTunnel, not legacy runLoop batch.
func TestIngressMaybeStartUsesSymmetricRunTunnel(t *testing.T) {
	host := &symmetricPumpTestHost{pktCh: make(chan []byte, 4)}
	ing := New(host)
	sub := ing.RegisterUDPSubscriber(53000)
	defer ing.UnregisterUDPSubscriber(sub)

	ing.MaybeStart(false)
	if !ing.running.Load() {
		t.Fatal("expected ingress pump running")
	}

	src := netip.MustParseAddr("10.200.0.2")
	dst := netip.MustParseAddr("198.18.0.2")
	pkt, err := cipframe.BuildIPv4UDPPacket(src, 53, dst, 53000, []byte("sym"))
	if err != nil {
		t.Fatalf("build udp: %v", err)
	}
	host.pktCh <- pkt

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		select {
		case got := <-sub.Ch:
			if len(got) == len(pkt) {
				ing.StopGracefully()
				if host.readerCalls.Load() < 1 {
					t.Fatal("expected symmetric pump to read wire")
				}
				if host.flushAck.Load() < 1 {
					t.Fatal("expected LoopOut end flush after dispatch")
				}
				return
			}
		default:
			time.Sleep(time.Millisecond)
		}
	}
	ing.StopGracefully()
	t.Fatal("timed out waiting for UDP bridge delivery via RunTunnel demux")
}
