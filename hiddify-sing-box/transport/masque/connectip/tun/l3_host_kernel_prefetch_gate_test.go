package tun

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	cippump "github.com/sagernet/sing-box/transport/masque/connectip/pump"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
)

// prefetchHostEgress simulates sing-tun ReadHostEgress queue (PERF-3 virtio batch / drain).
type prefetchHostEgress struct {
	mu sync.Mutex
	q  [][]byte
}

func (p *prefetchHostEgress) read(ctx context.Context, buf []byte) (int, error) {
	p.mu.Lock()
	if len(p.q) > 0 {
		pkt := p.q[0]
		p.q = p.q[1:]
		p.mu.Unlock()
		return copy(buf, pkt), nil
	}
	p.mu.Unlock()
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	default:
		return 0, nil
	}
}

func (p *prefetchHostEgress) fill(pkts ...[]byte) {
	p.mu.Lock()
	p.q = append(p.q, pkts...)
	p.mu.Unlock()
}

// TestL3HostKernelTunPrefetchSim (GATE-UP-5) prefetch queue → many pkts per flush without extra tun syscalls.
func TestL3HostKernelTunPrefetchSim(t *testing.T) {
	tunHost := netip.MustParseAddr("172.19.100.2")
	wireLocal := netip.MustParseAddr("198.18.0.1")
	server := netip.MustParseAddr("198.18.0.99")
	prefixes := []netip.Prefix{netip.MustParsePrefix(server.String() + "/32")}
	bulk := makeIPv4TCPPayload(tunHost, server, 40000, 5201, byte(header.TCPFlagAck|header.TCPFlagPsh), make([]byte, 512))

	const burst = 24
	pf := &prefetchHostEgress{}
	for i := 0; i < burst; i++ {
		pf.fill(bulk)
	}

	w := &mockL3Writer{}
	b := NewL3OverlayBridge(func(p []byte) (int, error) { return len(p), nil }, w, &mockL3Reader{}, OverlayNAT{
		TunHost: tunHost, WireLocal: wireLocal,
	})
	b.SetHostEgressRead(pf.read, prefixes)
	b.SetPumpWakeHooks(cippump.WakeHooks{}, func() { w.FlushEgressBatch() })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = b.RunPump(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for w.inPlace.Load()+w.noWakeWrites.Load() < burst && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()

	writes := w.inPlace.Load() + w.noWakeWrites.Load()
	fl := w.flushes.Load()
	if writes < burst {
		t.Fatalf("writes=%d want >= %d", writes, burst)
	}
	ratio := float64(writes) / float64(max64(int64(fl), 1))
	if ratio < 8 {
		t.Fatalf("prefetch pkts/flush=%.1f want >=8 (writes=%d flushes=%d)", ratio, writes, fl)
	}
	t.Logf("prefetch sim: writes=%d flushes=%d pkts/flush=%.1f", writes, fl, ratio)
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
