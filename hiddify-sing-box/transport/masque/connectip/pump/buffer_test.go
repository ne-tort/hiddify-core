package pump

import (
	"testing"

	cipnet "github.com/sagernet/sing-box/transport/masque/connectip/netstack"
)

func TestNetBufferHeadroomLayout(t *testing.T) {
	pool := NewNetBuffer(128)
	payload := pool.Get()
	if cap(payload) != 128+ProxiedIPDatagramHeadroom {
		t.Fatalf("payload cap=%d want %d", cap(payload), 128+ProxiedIPDatagramHeadroom)
	}
	if !IsOutboundPoolPayload(payload) {
		t.Fatal("expected headroom-backed payload slice")
	}
	frame, ok := cipnet.FrameFromOutboundIP(payload[:20], 5)
	if !ok {
		t.Fatal("FrameFromOutboundIP: expected ok for pump pool slice")
	}
	if len(frame) != 25 {
		t.Fatalf("frame len=%d want 25", len(frame))
	}
	pool.Put(payload)
}

func TestTryReturnOutboundPayloadPumpPool(t *testing.T) {
	payload := DefaultNetBuffer().Get()
	payload = payload[:64]
	if !TryReturnOutboundPayload(payload) {
		t.Fatal("TryReturnOutboundPayload: expected pump pool return")
	}
}

func TestNetBufferPool(t *testing.T) {
	t.Parallel()
	pool := NewNetBuffer(128)
	b1 := pool.Get()
	if cap(b1) != 128+ProxiedIPDatagramHeadroom {
		t.Fatalf("cap = %d", cap(b1))
	}
	pool.Put(b1)
	b2 := pool.Get()
	if cap(b2) != 128+ProxiedIPDatagramHeadroom {
		t.Fatalf("reused cap = %d", cap(b2))
	}
}
