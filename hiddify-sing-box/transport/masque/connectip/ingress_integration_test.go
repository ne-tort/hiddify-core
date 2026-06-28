package connectip

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip/header"
)

func TestDeliverTCPIngressNoPath(t *testing.T) {
	pkt := buildIngressTestIPv4TCP(t, 0x10, nil)
	if ok := DeliverTCPIngress(pkt, TCPIngressDeliverHooks{}); ok {
		t.Fatal("expected false with empty hooks")
	}
}

func TestDeliverTCPIngressPreTCPInflight(t *testing.T) {
	pkt := buildIngressTestIPv4TCP(t, 0x10, nil)
	host := &ingressIntegrationTestHost{}
	ing := NewIngress(host)

	var enqueued int
	ok := DeliverTCPIngress(pkt, TCPIngressDeliverHooks{
		InstallInflight: func() bool { return true },
		EnqueuePreTCP: func(p []byte) {
			enqueued++
			ing.EnqueuePreTCP(p)
		},
	})
	if !ok || enqueued != 1 {
		t.Fatalf("ok=%v enqueued=%d want ok=true enqueued=1", ok, enqueued)
	}
	if ing.PreTCPBuffered() != 1 {
		t.Fatalf("buffered=%d want 1", ing.PreTCPBuffered())
	}
}

func TestDeliverTCPIngressActiveNetstack(t *testing.T) {
	sess := &packetPipeSession{
		recvCh:  make(chan []byte, 8),
		sendCh:  make(chan []byte, 8),
		closeCh: make(chan struct{}),
	}
	stack, err := NewNetstack(context.Background(), sess, NetstackOptions{
		LocalIPv4: netip.MustParseAddr("198.18.0.2"),
		LocalIPv6: netip.MustParseAddr("fd00::2"),
	})
	if err != nil {
		t.Fatalf("create stack: %v", err)
	}
	defer stack.Close()

	pkt := buildIngressTestIPv4TCP(t, 0x10, []byte("payload"))
	var wakeNotes atomic.Int32
	ok := DeliverTCPIngress(pkt, TCPIngressDeliverHooks{
		ActiveNetstack: func() IngressNetstack { return stack },
		OnAfterDeliver: func([]byte, IngressNetstack) { wakeNotes.Add(1) },
	})
	if !ok {
		t.Fatal("expected deliver via active netstack")
	}
	if wakeNotes.Load() != 1 {
		t.Fatalf("wakeNotes=%d want 1", wakeNotes.Load())
	}
}

func TestDeliverTCPIngressAckOnlySchedulesOutboundDrain(t *testing.T) {
	sess := &packetPipeSession{
		recvCh:  make(chan []byte, 8),
		sendCh:  make(chan []byte, 8),
		closeCh: make(chan struct{}),
	}
	stack, err := NewNetstack(context.Background(), sess, NetstackOptions{
		LocalIPv4: netip.MustParseAddr("198.18.0.2"),
		LocalIPv6: netip.MustParseAddr("fd00::2"),
	})
	if err != nil {
		t.Fatalf("create stack: %v", err)
	}
	defer stack.Close()

	ackOnly := buildIngressTestIPv4TCP(t, 0x10, nil)
	if IPv4TCPHasPayload(ackOnly) {
		t.Fatal("ACK-only fixture must not carry payload")
	}
	ok := DeliverTCPIngress(ackOnly, TCPIngressDeliverHooks{
		ActiveNetstack: func() IngressNetstack { return stack },
	})
	if !ok {
		t.Fatal("expected deliver for ACK-only segment")
	}
	// W-IP-ARCH-1: IPv4TCPIngressWakeCandidate schedules outbound drain (queue may stay empty in fixture).
}

func TestDeliverTCPIngressPayloadSchedulesOutboundDrain(t *testing.T) {
	sess := &packetPipeSession{
		recvCh:  make(chan []byte, 8),
		sendCh:  make(chan []byte, 8),
		closeCh: make(chan struct{}),
	}
	stack, err := NewNetstack(context.Background(), sess, NetstackOptions{
		LocalIPv4: netip.MustParseAddr("198.18.0.2"),
		LocalIPv6: netip.MustParseAddr("fd00::2"),
	})
	if err != nil {
		t.Fatalf("create stack: %v", err)
	}
	defer stack.Close()

	withPayload := buildIngressTestIPv4TCP(t, 0x10, []byte("payload"))
	if !IPv4TCPHasPayload(withPayload) {
		t.Fatal("fixture must carry TCP payload")
	}
	ok := DeliverTCPIngress(withPayload, TCPIngressDeliverHooks{
		ActiveNetstack: func() IngressNetstack { return stack },
	})
	if !ok {
		t.Fatal("expected deliver for payload segment")
	}
	stack.ScheduleOutboundDrain()
	if depth := stack.OutboundQueueDepth(); depth != 0 {
		t.Fatalf("sync egress queue depth=%d want 0", depth)
	}
}

func TestDeliverTCPIngressInjectFallback(t *testing.T) {
	sess := &packetPipeSession{
		recvCh:  make(chan []byte, 8),
		sendCh:  make(chan []byte, 8),
		closeCh: make(chan struct{}),
	}
	stack, err := NewNetstack(context.Background(), sess, NetstackOptions{
		LocalIPv4: netip.MustParseAddr("198.18.0.2"),
		LocalIPv6: netip.MustParseAddr("fd00::2"),
	})
	if err != nil {
		t.Fatalf("create stack: %v", err)
	}
	defer stack.Close()

	pkt := buildIngressTestIPv4TCP(t, 0x10, nil)
	ok := DeliverTCPIngress(pkt, TCPIngressDeliverHooks{
		ActiveNetstack:    func() IngressNetstack { return nil },
		InstallInflight:   func() bool { return false },
		NetstackForInject: func() IngressNetstack { return stack },
	})
	if !ok {
		t.Fatal("expected deliver via inject fallback netstack")
	}
}

func TestPreTCPIngressDropObsCounter(t *testing.T) {
	host := &ingressIntegrationTestHost{}
	ing := NewIngress(host)
	pkt := []byte{0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2}
	for i := 0; i < PreTCPNetstackIngressMax; i++ {
		ing.EnqueuePreTCP(pkt)
	}
	before := ObservabilitySnapshot()["connect_ip_pre_tcp_ingress_drop_total"].(uint64)
	ing.EnqueuePreTCP(pkt)
	after := ObservabilitySnapshot()["connect_ip_pre_tcp_ingress_drop_total"].(uint64)
	if after != before+1 {
		t.Fatalf("pre_tcp drop counter: before=%d after=%d want +1", before, after)
	}
}

func TestFlushPreTCPUsesOwnedFrames(t *testing.T) {
	host := &ingressIntegrationTestHost{}
	ing := NewIngress(host)
	pkt := buildIngressTestIPv4TCP(t, 0x10, []byte("x"))
	ing.EnqueuePreTCP(pkt)

	sess := &packetPipeSession{
		recvCh:  make(chan []byte, 8),
		sendCh:  make(chan []byte, 8),
		closeCh: make(chan struct{}),
	}
	ns, err := NewNetstack(context.Background(), sess, NetstackOptions{
		LocalIPv4: netip.MustParseAddr("198.18.0.2"),
		LocalIPv6: netip.MustParseAddr("fd00::2"),
	})
	if err != nil {
		t.Fatalf("create stack: %v", err)
	}
	defer ns.Close()

	ing.FlushPreTCP(ns)
	if ing.PreTCPBuffered() != 0 {
		t.Fatalf("buffered=%d want 0 after flush", ing.PreTCPBuffered())
	}
}

// TestIngressBurstUsqueImmediateOneAckWakePerPacket verifies U0-1: symmetric RunTunnel
// flushes ingress ACK wake once per LoopOut iteration (usque immediate), not batched CM coalesce.
func TestIngressBurstUsqueImmediateOneAckWakePerPacket(t *testing.T) {
	sess := &packetPipeSession{
		recvCh:  make(chan []byte, 8),
		sendCh:  make(chan []byte, 8),
		closeCh: make(chan struct{}),
	}
	stack, err := NewNetstack(context.Background(), sess, NetstackOptions{
		LocalIPv4: netip.MustParseAddr("198.18.0.2"),
		LocalIPv6: netip.MustParseAddr("fd00::2"),
	})
	if err != nil {
		t.Fatalf("create stack: %v", err)
	}
	defer stack.Close()

	pkts := [][]byte{
		buildIngressTestIPv4TCP(t, 0x10, []byte("a")),
		buildIngressTestIPv4TCP(t, 0x10, []byte("b")),
		buildIngressTestIPv4TCP(t, 0x10, []byte("c")),
	}
	host := &ingressBurstIntegrationHost{
		ns:   stack,
		pkts: pkts,
	}
	ing := NewIngress(host)
	ing.MaybeStart(true)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if host.delivers.Load() >= 3 && host.flushes.Load() >= 3 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	defer ing.StopGracefully()

	if host.delivers.Load() != 3 {
		t.Fatalf("delivers=%d want 3", host.delivers.Load())
	}
	if host.flushes.Load() != 3 {
		t.Fatalf("flushes=%d want 3 (one ACK wake per datagram under usque immediate)", host.flushes.Load())
	}
}

func buildIngressTestIPv4TCP(t *testing.T, flags byte, payload []byte) []byte {
	t.Helper()
	ihl := 20
	doff := int(header.TCPMinimumSize)
	total := ihl + doff + len(payload)
	pkt := make([]byte, total)
	pkt[0] = 0x45
	pkt[9] = byte(header.TCPProtocolNumber)
	pkt[ihl+12] = 0x50
	pkt[ihl+13] = flags
	if len(payload) > 0 {
		copy(pkt[ihl+doff:], payload)
	}
	return pkt
}

type ingressIntegrationTestHost struct{}

func (h *ingressIntegrationTestHost) IngressTransportModeOK() bool { return true }
func (h *ingressIntegrationTestHost) IngressPacketReader() func(context.Context, []byte) (int, error) {
	return nil
}
func (h *ingressIntegrationTestHost) IngressTCPInstallInflight() bool        { return false }
func (h *ingressIntegrationTestHost) IngressTCPNetstack() IngressNetstack          { return nil }
func (h *ingressIntegrationTestHost) IngressTCPNetstackForInject() IngressNetstack { return nil }
func (h *ingressIntegrationTestHost) IngressTCPFastPath([]byte) bool         { return false }
func (h *ingressIntegrationTestHost) IngressDeliverTCPNoFlush([]byte) bool  { return false }
func (h *ingressIntegrationTestHost) IngressFlushAckWake()                  {}
func (h *ingressIntegrationTestHost) IngressFlushEgressBatch()              {}
func (h *ingressIntegrationTestHost) IngressWritePacket() func([]byte) ([]byte, error) {
	return nil
}
func (h *ingressIntegrationTestHost) IngressOnReadFatal(error)              {}
func (h *ingressIntegrationTestHost) IngressDebugLog([]byte, int, bool, bool) {}
func (h *ingressIntegrationTestHost) IngressObsEvent(string)                {}
func (h *ingressIntegrationTestHost) IngressEngineDrop(string)              {}
func (h *ingressIntegrationTestHost) IngressReadDrop(string)                {}
func (h *ingressIntegrationTestHost) IngressSessionReset(string)            {}

type ingressBurstIntegrationHost struct {
	ns       *Netstack
	pkts     [][]byte
	readIdx  int
	delivers atomic.Int32
	flushes  atomic.Int32
}

func (h *ingressBurstIntegrationHost) IngressTransportModeOK() bool { return true }

func (h *ingressBurstIntegrationHost) IngressPacketReader() func(context.Context, []byte) (int, error) {
	return func(ctx context.Context, buf []byte) (int, error) {
		if h.readIdx >= len(h.pkts) {
			if err := ctx.Err(); err != nil {
				return 0, err
			}
			return 0, context.Canceled
		}
		if ctx.Err() != nil && h.readIdx == 0 {
			return 0, ctx.Err()
		}
		pkt := h.pkts[h.readIdx]
		h.readIdx++
		return copy(buf, pkt), nil
	}
}

func (h *ingressBurstIntegrationHost) IngressTCPInstallInflight() bool        { return false }
func (h *ingressBurstIntegrationHost) IngressTCPNetstack() IngressNetstack          { return h.ns }
func (h *ingressBurstIntegrationHost) IngressTCPNetstackForInject() IngressNetstack { return h.ns }

func (h *ingressBurstIntegrationHost) IngressTCPFastPath(pkt []byte) bool {
	return TCPIngressFastPath(pkt, true, h.ns != nil, false)
}

func (h *ingressBurstIntegrationHost) IngressDeliverTCPNoFlush(pkt []byte) bool {
	if !DeliverTCPIngress(pkt, WireTCPIngressDeliverFromStruct(
		func() *Netstack { return h.ns },
		func() bool { return false },
		func() *Netstack { return h.ns },
		nil,
		func([]byte, *Netstack) { h.delivers.Add(1) },
	)) {
		return false
	}
	return true
}

func (h *ingressBurstIntegrationHost) IngressFlushAckWake() { h.flushes.Add(1) }

func (h *ingressBurstIntegrationHost) IngressFlushEgressBatch() {}

func (h *ingressBurstIntegrationHost) IngressWritePacket() func([]byte) ([]byte, error) {
	return func([]byte) ([]byte, error) { return nil, nil }
}

func (h *ingressBurstIntegrationHost) IngressOnReadFatal(error)              {}
func (h *ingressBurstIntegrationHost) IngressDebugLog([]byte, int, bool, bool) {}
func (h *ingressBurstIntegrationHost) IngressObsEvent(string)                  {}
func (h *ingressBurstIntegrationHost) IngressEngineDrop(string)                {}
func (h *ingressBurstIntegrationHost) IngressReadDrop(string)                  {}
func (h *ingressBurstIntegrationHost) IngressSessionReset(string)              {}
