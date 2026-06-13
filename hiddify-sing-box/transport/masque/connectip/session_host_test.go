package connectip

import (
	"context"
	"net/netip"
	"testing"
)

func TestWireTCPIngressDeliverActiveNetstack(t *testing.T) {
	t.Parallel()

	pkt := []byte{
		0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
		10, 0, 0, 1, 10, 0, 0, 2, 0x30, 0x39, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	sess := &packetPipeSession{
		recvCh:  make(chan []byte, 4),
		sendCh:  make(chan []byte, 4),
		closeCh: make(chan struct{}),
	}
	ns, err := NewNetstack(context.Background(), sess, NetstackOptions{
		LocalIPv4: netip.MustParseAddr("198.18.0.2"),
		LocalIPv6: netip.MustParseAddr("fd00::2"),
	})
	if err != nil {
		t.Fatalf("NewNetstack: %v", err)
	}
	defer ns.Close()

	var afterDeliver int
	hooks := WireTCPIngressDeliver(
		func() *Netstack { return ns },
		func() bool { return false },
		func() *Netstack { return nil },
		nil,
		func([]byte, *Netstack) { afterDeliver++ },
	)
	if !DeliverTCPIngress(pkt, hooks) {
		t.Fatal("expected deliver via active netstack")
	}
	if afterDeliver != 1 {
		t.Fatalf("OnAfterDeliver: want 1, got %d", afterDeliver)
	}
}

func TestWireTCPIngressDeliverEnqueuePreTCP(t *testing.T) {
	t.Parallel()

	pkt := []byte{0x45, 0x00, 0x00, 0x14}
	var enqueued []byte
	hooks := WireTCPIngressDeliver(
		func() *Netstack { return nil },
		func() bool { return true },
		func() *Netstack { return nil },
		func(p []byte) { enqueued = append([]byte(nil), p...) },
		nil,
	)
	if !DeliverTCPIngress(pkt, hooks) {
		t.Fatal("expected pre-TCP enqueue path")
	}
	if len(enqueued) != len(pkt) {
		t.Fatalf("enqueue len: want %d, got %d", len(pkt), len(enqueued))
	}
}
