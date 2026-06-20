package connectip

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
)

func TestDeliverTCPIngressNoPath(t *testing.T) {
	pkt := buildTestIPv4TCP(t, 0x10, nil)
	if ok := DeliverTCPIngress(pkt, TCPIngressDeliverHooks{}); ok {
		t.Fatal("expected false with empty hooks")
	}
}

func TestDeliverTCPIngressPreTCPInflight(t *testing.T) {
	pkt := buildTestIPv4TCP(t, 0x10, nil)
	host := &ingressTestHost{}
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

	pkt := buildTestIPv4TCP(t, 0x10, []byte("payload"))
	var wakeNotes atomic.Int32
	ok := DeliverTCPIngress(pkt, TCPIngressDeliverHooks{
		ActiveNetstack: func() *Netstack { return stack },
		OnAfterDeliver: func([]byte, *Netstack) { wakeNotes.Add(1) },
	})
	if !ok {
		t.Fatal("expected deliver via active netstack")
	}
	if wakeNotes.Load() != 1 {
		t.Fatalf("wakeNotes=%d want 1", wakeNotes.Load())
	}
}

func TestDeliverTCPIngressAckOnlySkipsOutboundDrain(t *testing.T) {
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

	ackOnly := buildTestIPv4TCP(t, 0x10, nil)
	if IPv4TCPHasPayload(ackOnly) {
		t.Fatal("ACK-only fixture must not carry payload")
	}
	ok := DeliverTCPIngress(ackOnly, TCPIngressDeliverHooks{
		ActiveNetstack: func() *Netstack { return stack },
	})
	if !ok {
		t.Fatal("expected deliver for ACK-only segment")
	}
	if depth := stack.OutboundQueueDepth(); depth != 0 {
		t.Fatalf("ACK-only ingress must not queue egress (depth=%d)", depth)
	}
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

	withPayload := buildTestIPv4TCP(t, 0x10, []byte("payload"))
	if !IPv4TCPHasPayload(withPayload) {
		t.Fatal("fixture must carry TCP payload")
	}
	ok := DeliverTCPIngress(withPayload, TCPIngressDeliverHooks{
		ActiveNetstack: func() *Netstack { return stack },
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

	pkt := buildTestIPv4TCP(t, 0x10, nil)
	ok := DeliverTCPIngress(pkt, TCPIngressDeliverHooks{
		ActiveNetstack:    func() *Netstack { return nil },
		InstallInflight:   func() bool { return false },
		NetstackForInject: func() *Netstack { return stack },
	})
	if !ok {
		t.Fatal("expected deliver via inject fallback netstack")
	}
}
