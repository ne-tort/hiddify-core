package relay

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

type mockH2BatchDownlink struct {
	appendN atomic.Int32
	flushN  atomic.Int32
}

func (m *mockH2BatchDownlink) WriteUDPPayloadAsCapsules([]byte) error { return nil }

func (m *mockH2BatchDownlink) AppendUDPPayloadAsCapsules([]byte) error {
	m.appendN.Add(1)
	return nil
}

func (m *mockH2BatchDownlink) FlushPending() error {
	m.flushN.Add(1)
	return nil
}

// TestRelayH2ConnectDownlinkFlushesAtMaxBatchWire locks bulk S2C flush when tailFlush is false (asymmetric echo coalescing preserved for small batches).
func TestRelayH2ConnectDownlinkFlushesAtMaxBatchWire(t *testing.T) {
	t.Parallel()
	relayConn, peer := dialConnectedUDPPair(t)
	mock := &mockH2BatchDownlink{}
	const maxWire = 400 // single 512B proxied payload wire (~515B RFC9297) exceeds this cap
	payload := make([]byte, 512)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = RelayH2ConnectDownlink(ctx, relayConn, 65535, mock, maxWire, func([][]byte) bool { return false })
	}()

	deadline := time.Now().Add(2 * time.Second)
	for mock.flushN.Load() == 0 && time.Now().Before(deadline) {
		if _, err := peer.WriteTo(payload, relayConn.LocalAddr()); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done

	if mock.appendN.Load() < 1 {
		t.Fatalf("append calls=%d want >=1", mock.appendN.Load())
	}
	if mock.flushN.Load() < 1 {
		t.Fatal("expected FlushPending when batch wire >= maxBatchWire with tailFlush false")
	}
}
