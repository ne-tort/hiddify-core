package forwarder

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestResolveConnectIPEgress(t *testing.T) {
	t.Setenv("MASQUE_CONNECT_IP_EGRESS", "")
	if got := ResolveConnectIPEgress(""); got != ConnectIPEgressPacket {
		t.Fatalf("default got %q want packet", got)
	}
	if got := ResolveConnectIPEgress("terminate"); got != ConnectIPEgressTerminate {
		t.Fatalf("option terminate got %q", got)
	}
	if ConnectIPEgressIsExplicit("") {
		t.Fatal("empty option want not explicit")
	}
	if !ConnectIPEgressIsExplicit("packet") {
		t.Fatal("option packet want explicit")
	}
	t.Setenv("MASQUE_CONNECT_IP_EGRESS", "terminate")
	if got := ResolveConnectIPEgress("packet"); got != ConnectIPEgressTerminate {
		t.Fatalf("env override got %q", got)
	}
	if !ConnectIPEgressIsExplicit("") {
		t.Fatal("env set want explicit")
	}
}

func TestChannelHandoffPacketPlaneRelay(t *testing.T) {
	wire := newMockPacketPlane()
	dev := NewChannelHandoffDevice(8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = RunConnectIPPacketPlaneRelay(ctx, wire, dev)
	}()

	// Peer→CIP: inject into device → should appear as wire WritePacket (LoopIn: device read → wire write)
	pkt := []byte{0x45, 0x00, 0x00, 0x14, 0, 0, 0, 0, 64, 1, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8}
	if !dev.InjectFromPeer(pkt) {
		t.Fatal("InjectFromPeer failed")
	}
	deadline := time.After(2 * time.Second)
	for {
		wire.mu.Lock()
		n := len(wire.written)
		wire.mu.Unlock()
		if n > 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timeout waiting CIP write from peer inject")
		case <-time.After(10 * time.Millisecond):
		}
	}

	// CIP→peer: wire ReadPacket feeds LoopOut → device WritePacket → ToPeer
	c2s := []byte{0x45, 0x00, 0x00, 0x14, 0, 0, 0, 0, 64, 6, 0, 0, 8, 8, 8, 8, 1, 2, 3, 4}
	wire.pushRead(c2s)
	select {
	case got := <-dev.ToPeer():
		if len(got) != len(c2s) {
			t.Fatalf("toPeer len=%d want %d", len(got), len(c2s))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting handoff ToPeer")
	}

	cancel()
	wg.Wait()
}

type mockPacketPlane struct {
	mu      sync.Mutex
	readCh  chan []byte
	written [][]byte
	closed  bool
}

func newMockPacketPlane() *mockPacketPlane {
	return &mockPacketPlane{readCh: make(chan []byte, 16)}
}

func (m *mockPacketPlane) pushRead(pkt []byte) {
	m.readCh <- append([]byte(nil), pkt...)
}

func (m *mockPacketPlane) ReadPacket(buf []byte) (int, error) {
	pkt := <-m.readCh
	return copy(buf, pkt), nil
}

func (m *mockPacketPlane) WritePacket(buffer []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.written = append(m.written, append([]byte(nil), buffer...))
	return nil, nil
}

func (m *mockPacketPlane) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.closed {
		m.closed = true
		close(m.readCh)
	}
	return nil
}

func (m *mockPacketPlane) CurrentPeerPrefixes() []netip.Prefix { return nil }
