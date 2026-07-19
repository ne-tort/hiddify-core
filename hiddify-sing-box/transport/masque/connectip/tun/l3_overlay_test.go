package tun

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	cippump "github.com/sagernet/sing-box/transport/masque/connectip/pump"
	fwd "github.com/sagernet/sing-box/transport/masque/forwarder"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
)

type mockL3Writer struct {
	writes       atomic.Int32
	noWakeWrites atomic.Int32
	inPlace      atomic.Int32
	flushes      atomic.Int32
	retainNext   atomic.Bool
	lastPkt      atomic.Value // []byte
	inPlaceDelay time.Duration
}

func (m *mockL3Writer) WritePacket(p []byte) ([]byte, error) {
	m.writes.Add(1)
	m.lastPkt.Store(append([]byte(nil), p...))
	return nil, nil
}

func (m *mockL3Writer) WritePacketNoWake(p []byte) ([]byte, error) {
	m.noWakeWrites.Add(1)
	m.lastPkt.Store(append([]byte(nil), p...))
	return nil, nil
}

func (m *mockL3Writer) WritePacketInPlaceNoWake(p []byte) (retained bool, icmp []byte, err error) {
	if m != nil && m.inPlaceDelay > 0 {
		upload524SpinDelay(m.inPlaceDelay)
	}
	m.inPlace.Add(1)
	if m != nil && m.retainNext.Load() {
		m.lastPkt.Store(p)
		return true, nil, nil
	}
	m.lastPkt.Store(append([]byte(nil), p...))
	return false, nil, nil
}

func (m *mockL3Writer) lastPacket() []byte {
	if v := m.lastPkt.Load(); v != nil {
		if p, ok := v.([]byte); ok {
			return p
		}
	}
	return nil
}

func (m *mockL3Writer) FlushEgressBatch() {
	m.flushes.Add(1)
}

func (m *mockL3Writer) wireWrites() int32 {
	return m.writes.Load() + m.inPlace.Load() + m.noWakeWrites.Load()
}

func TestL3OverlaySendEnqueuesForLoopIn(t *testing.T) {
	w := &mockL3Writer{}
	reader := &mockL3Reader{}
	b := NewL3OverlayBridge(nil, w, reader, OverlayNAT{})
	b.SetStackIngressInject(func([]byte) error { return nil })
	b.SetPumpWakeHooks(cippump.WakeHooks{}, func() { w.FlushEgressBatch() })
	pkt := []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 0, 0, 0, 127, 0, 0, 1, 127, 0, 0, 2}
	if err := b.Send(pkt); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if w.writes.Load() != 0 {
		t.Fatalf("writes=%d want 0 before LoopIn drains", w.writes.Load())
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- b.RunPump(ctx)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for w.wireWrites() < 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done

	if w.wireWrites() != 1 {
		t.Fatalf("wireWrites=%d want 1 after LoopIn drain", w.wireWrites())
	}
	if w.flushes.Load() != 1 {
		t.Fatalf("flushes=%d want 1 (R2 batch flush after LoopIn batch)", w.flushes.Load())
	}
}

// TestL3OverlayHostEgressReadRelay verifies usque parity: LoopIn reads tun fd via HostEgressReader, not egressCh.
func TestL3OverlayHostEgressReadRelay(t *testing.T) {
	tunHost := netip.MustParseAddr("172.19.100.2")
	wireLocal := netip.MustParseAddr("198.18.0.1")
	server := netip.MustParseAddr("198.18.0.99")
	prefixes := []netip.Prefix{netip.MustParsePrefix(server.String() + "/32")}
	payload := []byte("bulk-download-chunk")
	egress := makeIPv4TCPPayload(tunHost, server, 40000, 5201, byte(header.TCPFlagAck|header.TCPFlagPsh), payload)

	var hostReads atomic.Int32
	hostRead := HostEgressReader(func(ctx context.Context, buf []byte) (int, error) {
		if hostReads.Add(1) > 1 {
			<-ctx.Done()
			return 0, ctx.Err()
		}
		return copy(buf, egress), nil
	})

	w := &mockL3Writer{}
	b := NewL3OverlayBridge(func(p []byte) (int, error) {
		return len(p), nil
	}, w, &mockL3Reader{}, OverlayNAT{
		TunHost:   tunHost,
		WireLocal: wireLocal,
	})
	b.SetHostEgressRead(hostRead, prefixes)
	b.SetPumpWakeHooks(cippump.WakeHooks{}, func() { w.FlushEgressBatch() })

	if err := b.Send(egress); err != nil {
		t.Fatalf("Send with host egress: %v", err)
	}
	if w.writes.Load() != 0 {
		t.Fatalf("writes=%d want 0 (Send no-op when host egress wired)", w.writes.Load())
	}
	// P2-8: host path must not fill egressCh (idle channel; LoopIn uses HostEgressReader).
	if n := len(b.egressCh); n != 0 {
		t.Fatalf("egressCh len=%d want 0 after host-path Send no-op", n)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- b.RunPump(ctx)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for w.wireWrites() < 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done

	if hostReads.Load() < 1 {
		t.Fatalf("hostReads=%d want >= 1", hostReads.Load())
	}
	if w.wireWrites() != 1 {
		t.Fatalf("wireWrites=%d want 1 after LoopIn host read", w.wireWrites())
	}
	wirePkt := w.lastPacket()
	if src, ok := ipv4Source(wirePkt); !ok || src != wireLocal {
		t.Fatalf("wire src=%v want SNAT %v", src, wireLocal)
	}
	if dst, ok := ipv4Destination(wirePkt); !ok || dst != server {
		t.Fatalf("wire dst=%v want %v", dst, server)
	}
}

// TestL3HostKernelBulkSyncBulkNoWakeAckSync bulk → NoWake; ACK → sync flush (same iter).
func TestL3HostKernelBulkSyncBulkNoWakeAckSync(t *testing.T) {
	tunHost := netip.MustParseAddr("172.19.100.2")
	wireLocal := netip.MustParseAddr("198.18.0.1")
	server := netip.MustParseAddr("198.18.0.99")
	prefixes := []netip.Prefix{netip.MustParsePrefix(server.String() + "/32")}
	bulk := makeIPv4TCPPayload(tunHost, server, 40000, 5201, byte(header.TCPFlagAck|header.TCPFlagPsh), make([]byte, 512))
	ack := makeIPv4TCPAck(tunHost, server, 40000, 5201, byte(header.TCPFlagAck))

	var hostReads atomic.Int32
	hostRead := HostEgressReader(func(ctx context.Context, buf []byte) (int, error) {
		switch hostReads.Add(1) {
		case 1:
			return copy(buf, bulk), nil
		case 2:
			return copy(buf, ack), nil
		default:
			<-ctx.Done()
			return 0, ctx.Err()
		}
	})

	w := &mockL3Writer{}
	b := NewL3OverlayBridge(func(p []byte) (int, error) { return len(p), nil }, w, &mockL3Reader{}, OverlayNAT{
		TunHost: tunHost, WireLocal: wireLocal,
	})
	b.SetHostEgressRead(hostRead, prefixes)
	b.SetPumpWakeHooks(cippump.WakeHooks{}, func() { w.FlushEgressBatch() })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = b.RunPump(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for w.wireWrites() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()

	if w.wireWrites() < 2 {
		t.Fatalf("bulk+ack wire=%d want >=2 (inPlace=%d noWake=%d writes=%d)",
			w.wireWrites(), w.inPlace.Load(), w.noWakeWrites.Load(), w.writes.Load())
	}
	if w.flushes.Load() < 1 {
		t.Fatalf("OnLoopInEnd flushes=%d want >=1", w.flushes.Load())
	}
}

// TestL3HostKernelBulkSyncBulkNoWakeSingleFlushPerIter (GATE-P0-1) coalesced bulk → one iter flush.
func TestL3HostKernelBulkSyncBulkNoWakeSingleFlushPerIter(t *testing.T) {
	tunHost := netip.MustParseAddr("172.19.100.2")
	wireLocal := netip.MustParseAddr("198.18.0.1")
	server := netip.MustParseAddr("198.18.0.99")
	prefixes := []netip.Prefix{netip.MustParsePrefix(server.String() + "/32")}
	bulk := makeIPv4TCPPayload(tunHost, server, 40000, 5201, byte(header.TCPFlagAck|header.TCPFlagPsh), make([]byte, 512))

	var hostReads atomic.Int32
	hostRead := HostEgressReader(func(ctx context.Context, buf []byte) (int, error) {
		n := int(hostReads.Add(1))
		if n <= 3 {
			return copy(buf, bulk), nil
		}
		<-ctx.Done()
		return 0, ctx.Err()
	})

	w := &mockL3Writer{}
	b := NewL3OverlayBridge(func(p []byte) (int, error) { return len(p), nil }, w, &mockL3Reader{}, OverlayNAT{
		TunHost: tunHost, WireLocal: wireLocal,
	})
	b.SetHostEgressRead(hostRead, prefixes)
	b.SetPumpWakeHooks(cippump.WakeHooks{}, func() { w.FlushEgressBatch() })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = b.RunPump(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for w.inPlace.Load()+w.noWakeWrites.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()

	if got := w.inPlace.Load() + w.noWakeWrites.Load(); got < 3 {
		t.Fatalf("bulk wire ops=%d want >=3", got)
	}
	if w.writes.Load() != 0 {
		t.Fatalf("sync writes=%d want 0 for bulk-only coalesce", w.writes.Load())
	}
	if fl := w.flushes.Load(); fl < 1 {
		t.Fatalf("OnLoopInEnd flushes=%d want >=1", fl)
	}
}

// TestL3HostKernelBulkSyncSmallPacketSyncFlush (GATE-P0-2) pure ACK uses copy NoWake + OnLoopInEnd flush.
func TestL3HostKernelBulkSyncSmallPacketSyncFlush(t *testing.T) {
	tunHost := netip.MustParseAddr("172.19.100.2")
	wireLocal := netip.MustParseAddr("198.18.0.1")
	server := netip.MustParseAddr("198.18.0.99")
	prefixes := []netip.Prefix{netip.MustParsePrefix(server.String() + "/32")}
	ack := makeIPv4TCPAck(tunHost, server, 40000, 5201, byte(header.TCPFlagAck))

	var hostReads atomic.Int32
	hostRead := HostEgressReader(func(ctx context.Context, buf []byte) (int, error) {
		if hostReads.Add(1) > 1 {
			<-ctx.Done()
			return 0, ctx.Err()
		}
		return copy(buf, ack), nil
	})

	w := &mockL3Writer{}
	b := NewL3OverlayBridge(func(p []byte) (int, error) { return len(p), nil }, w, &mockL3Reader{}, OverlayNAT{
		TunHost: tunHost, WireLocal: wireLocal,
	})
	b.SetHostEgressRead(hostRead, prefixes)
	b.SetPumpWakeHooks(cippump.WakeHooks{}, func() { w.FlushEgressBatch() })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = b.RunPump(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for w.noWakeWrites.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()

	if w.noWakeWrites.Load() < 1 {
		t.Fatalf("noWake=%d want >=1 for pure ACK copy NoWake", w.noWakeWrites.Load())
	}
	if w.flushes.Load() < 1 {
		t.Fatalf("flushes=%d want >=1 via OnLoopInEnd", w.flushes.Load())
	}
}

// TestL3HostKernelBulkSyncBulkThenAckDownloadAlive (GATE-P0-3) coalesced bulk + flush, then LoopOut ingress alive.
func TestL3HostKernelBulkSyncBulkThenAckDownloadAlive(t *testing.T) {
	tunHost := netip.MustParseAddr("172.19.100.2")
	wireLocal := netip.MustParseAddr("198.18.0.1")
	server := netip.MustParseAddr("172.30.99.2")
	prefixes := []netip.Prefix{netip.MustParsePrefix(server.String() + "/32")}
	bulk := makeIPv4TCPPayload(tunHost, server, 40000, 5201, byte(header.TCPFlagAck|header.TCPFlagPsh), make([]byte, 512))
	downBulk := makeIPv4TCPPayload(server, wireLocal, 5201, 40000, 0x18, make([]byte, 1000))

	var hostReads atomic.Int32
	hostRead := HostEgressReader(func(ctx context.Context, buf []byte) (int, error) {
		if hostReads.Add(1) > 2 {
			<-ctx.Done()
			return 0, ctx.Err()
		}
		return copy(buf, bulk), nil
	})

	var tunInjected atomic.Int32
	w := &mockL3Writer{}
	b := NewL3OverlayBridge(func(p []byte) (int, error) {
		tunInjected.Add(1)
		return len(p), nil
	}, w, &mockL3Reader{}, OverlayNAT{TunHost: tunHost, WireLocal: wireLocal})
	b.SetHostEgressRead(hostRead, prefixes)
	b.SetPumpWakeHooks(cippump.WakeHooks{}, func() { w.FlushEgressBatch() })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = b.RunPump(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for w.inPlace.Load()+w.noWakeWrites.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := w.inPlace.Load() + w.noWakeWrites.Load(); got < 2 {
		t.Fatalf("bulk NoWake ops=%d want >=2", got)
	}
	syncBeforeDown := w.writes.Load()
	if w.flushes.Load() < 1 {
		t.Fatalf("OnLoopInEnd flushes=%d want >=1 after bulk coalesce", w.flushes.Load())
	}

	if err := b.WritePacket(downBulk); err != nil {
		t.Fatalf("LoopOut WritePacket after bulk: %v", err)
	}
	if tunInjected.Load() < 1 {
		t.Fatalf("tunInjected=%d want >=1 (download ingress alive)", tunInjected.Load())
	}
	if w.writes.Load() != syncBeforeDown {
		t.Fatalf("LoopOut sync-relay writes=%d want %d", w.writes.Load(), syncBeforeDown)
	}
	cancel()
}

// TestGATEConnectIPPerf1bFullNoWakeDownloadRegression (GATE-P0-5) negative control: coalesced bulk
// NoWake without OnLoopInEnd flush leaves wire egress pending (pre-PERF-1b stall signature).
func TestGATEConnectIPPerf1bFullNoWakeDownloadRegression(t *testing.T) {
	tunHost := netip.MustParseAddr("172.19.100.2")
	wireLocal := netip.MustParseAddr("198.18.0.1")
	server := netip.MustParseAddr("172.30.99.2")
	prefixes := []netip.Prefix{netip.MustParsePrefix(server.String() + "/32")}
	bulk := makeIPv4TCPPayload(tunHost, server, 40000, 5201, byte(header.TCPFlagAck|header.TCPFlagPsh), make([]byte, 512))
	downBulk := makeIPv4TCPPayload(server, wireLocal, 5201, 40000, 0x18, make([]byte, 1000))

	var hostReads atomic.Int32
	hostRead := HostEgressReader(func(ctx context.Context, buf []byte) (int, error) {
		if hostReads.Add(1) > 2 {
			<-ctx.Done()
			return 0, ctx.Err()
		}
		return copy(buf, bulk), nil
	})

	w := &flushPendingWriter{inner: &mockL3Writer{}}
	var tunInjected atomic.Int32
	b := NewL3OverlayBridge(func(p []byte) (int, error) {
		tunInjected.Add(1)
		return len(p), nil
	}, w, &mockL3Reader{}, OverlayNAT{TunHost: tunHost, WireLocal: wireLocal})
	b.SetHostEgressRead(hostRead, prefixes)
	b.SetPumpWakeHooks(cippump.WakeHooks{}, nil) // regression: no OnLoopInEnd flush

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = b.RunPump(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for w.inner.wireWrites() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := w.inner.wireWrites(); got < 2 {
		t.Fatalf("bulk NoWake ops=%d want >=2", got)
	}
	if w.inner.flushes.Load() != 0 {
		t.Fatalf("negative control: flushes=%d want 0 without OnLoopInEnd", w.inner.flushes.Load())
	}
	if w.delivered.Load() != 0 {
		t.Fatalf("negative control: delivered=%d want 0 (NoWake pending until flush)", w.delivered.Load())
	}

	if err := b.WritePacket(downBulk); err != nil {
		t.Fatalf("LoopOut WritePacket after bulk: %v", err)
	}
	if tunInjected.Load() < 1 {
		t.Fatalf("tunInjected=%d want >=1 (LoopOut independent of egress flush)", tunInjected.Load())
	}
	if w.delivered.Load() != 0 {
		t.Fatalf("regression signature: delivered=%d want 0 without flush (contrast GATE-P0-3)", w.delivered.Load())
	}
	cancel()
}

// flushPendingWriter counts wire datagrams only after FlushEgressBatch (R2 batch parity).
type flushPendingWriter struct {
	inner     *mockL3Writer
	pending   atomic.Int32
	delivered atomic.Int32
}

func (w *flushPendingWriter) WritePacket(p []byte) ([]byte, error) {
	w.pending.Add(1)
	return w.inner.WritePacket(p)
}

func (w *flushPendingWriter) WritePacketNoWake(p []byte) ([]byte, error) {
	w.pending.Add(1)
	return w.inner.WritePacketNoWake(p)
}

func (w *flushPendingWriter) WritePacketInPlaceNoWake(p []byte) (bool, []byte, error) {
	w.pending.Add(1)
	return w.inner.WritePacketInPlaceNoWake(p)
}

func (w *flushPendingWriter) FlushEgressBatch() {
	w.inner.FlushEgressBatch()
	w.delivered.Store(w.pending.Load())
}

// TestL3HostKernelPumpInPlaceRetained (GATE-PERF-1c) host-kernel LoopIn retains pump pool buf on in-place wire write.
func TestL3HostKernelPumpInPlaceRetained(t *testing.T) {
	tunHost := netip.MustParseAddr("172.19.100.2")
	wireLocal := netip.MustParseAddr("198.18.0.1")
	server := netip.MustParseAddr("198.18.0.99")
	prefixes := []netip.Prefix{netip.MustParsePrefix(server.String() + "/32")}
	bulk := makeIPv4TCPPayload(tunHost, server, 40000, 5201, byte(header.TCPFlagAck|header.TCPFlagPsh), make([]byte, 512))

	var hostReads atomic.Int32
	hostRead := HostEgressReader(func(ctx context.Context, buf []byte) (int, error) {
		if hostReads.Add(1) > 2 {
			<-ctx.Done()
			return 0, ctx.Err()
		}
		return copy(buf, bulk), nil
	})

	w := &mockL3Writer{}
	w.retainNext.Store(true)
	b := NewL3OverlayBridge(func(p []byte) (int, error) { return len(p), nil }, w, &mockL3Reader{}, OverlayNAT{
		TunHost: tunHost, WireLocal: wireLocal,
	})
	b.SetHostEgressRead(hostRead, prefixes)
	b.SetPumpWakeHooks(cippump.WakeHooks{}, func() { w.FlushEgressBatch() })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = b.RunPump(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for hostReads.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()

	if w.inPlace.Load() < 1 {
		t.Fatalf("inPlace=%d want >=1", w.inPlace.Load())
	}
	if hostReads.Load() < 2 {
		t.Fatalf("hostReads=%d want >=2 after retained in-place write", hostReads.Load())
	}
}

// TestL3HostKernelDeepQueueCoalesceBurst (GATE-UP-1) deep host queue → many pkts per OnLoopInEnd flush.
func TestL3HostKernelDeepQueueCoalesceBurst(t *testing.T) {
	tunHost := netip.MustParseAddr("172.19.100.2")
	wireLocal := netip.MustParseAddr("198.18.0.1")
	server := netip.MustParseAddr("198.18.0.99")
	prefixes := []netip.Prefix{netip.MustParsePrefix(server.String() + "/32")}
	const segLen = 1310
	payload := make([]byte, segLen-20-20-20)
	bulk := makeIPv4TCPPayload(tunHost, server, 40000, 5201, byte(header.TCPFlagAck|header.TCPFlagPsh), payload)
	if len(bulk) < 1200 {
		t.Fatalf("bulk len=%d want MSS-ish", len(bulk))
	}

	const burst = 32
	var hostQ [][]byte
	for i := 0; i < burst; i++ {
		hostQ = append(hostQ, bulk)
	}
	hostRead := HostEgressReader(func(ctx context.Context, buf []byte) (int, error) {
		if len(hostQ) == 0 {
			<-ctx.Done()
			return 0, ctx.Err()
		}
		pkt := hostQ[0]
		hostQ = hostQ[1:]
		return copy(buf, pkt), nil
	})

	w := &mockL3Writer{}
	b := NewL3OverlayBridge(func(p []byte) (int, error) { return len(p), nil }, w, &mockL3Reader{}, OverlayNAT{
		TunHost: tunHost, WireLocal: wireLocal,
	})
	b.SetHostEgressRead(hostRead, prefixes)
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
		t.Fatalf("bulk wire ops=%d want >= %d", writes, burst)
	}
	if fl < 1 {
		t.Fatalf("flushes=%d want >= 1", fl)
	}
	ratio := float64(writes) / float64(fl)
	if ratio < 4 {
		t.Fatalf("pkts/flush=%.1f want >= 4 with deep queue (writes=%d flushes=%d)", ratio, writes, fl)
	}
	t.Logf("deep queue coalesce: writes=%d flushes=%d pkts/flush=%.1f seg=%d", writes, fl, ratio, len(bulk))
}

// TestL3HostKernelSpacedSinglePktPerRead (GATE-UP-3) depth-1 channel + 18µs spacing → coalesce batch ~5 pkts/flush, ~524 Mbit/s identity.
func TestL3HostKernelSpacedSinglePktPerRead(t *testing.T) {
	tunHost := netip.MustParseAddr("172.19.100.2")
	wireLocal := netip.MustParseAddr("198.18.0.1")
	server := netip.MustParseAddr("198.18.0.99")
	prefixes := []netip.Prefix{netip.MustParsePrefix(server.String() + "/32")}
	const segLen = 1310
	payload := make([]byte, segLen-20-20-20)
	bulk := makeIPv4TCPPayload(tunHost, server, 40000, 5201, byte(header.TCPFlagAck|header.TCPFlagPsh), payload)

	const burst = 20
	const spacing = 18 * time.Microsecond
	staged := make(chan []byte, 1)
	go func() {
		for i := 0; i < burst; i++ {
			staged <- bulk
			time.Sleep(spacing)
		}
		close(staged)
	}()

	hostRead := HostEgressReader(func(ctx context.Context, buf []byte) (int, error) {
		select {
		case pkt, ok := <-staged:
			if !ok {
				return 0, ctx.Err()
			}
			return copy(buf, pkt), nil
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	})

	w := &mockL3Writer{}
	b := NewL3OverlayBridge(func(p []byte) (int, error) { return len(p), nil }, w, &mockL3Reader{}, OverlayNAT{
		TunHost: tunHost, WireLocal: wireLocal,
	})
	b.SetHostEgressRead(hostRead, prefixes)
	b.SetPumpWakeHooks(cippump.WakeHooks{}, func() { w.FlushEgressBatch() })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	start := time.Now()
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
	if fl < 1 {
		t.Fatalf("flushes=%d want >= 1", fl)
	}
	ratio := float64(writes) / float64(fl)
	if ratio > 2.5 {
		t.Fatalf("depth-1 @ 18µs: pkts/flush=%.1f want <=2.5 (≈1 flush/pkt → 524 Mbit/s identity)", ratio)
	}
	elapsed := time.Since(start).Seconds()
	impliedMbps := float64(writes) * float64(len(bulk)) * 8 / elapsed / 1e6
	t.Logf("depth-1 spaced: writes=%d flushes=%d pkts/flush=%.2f wall=%.3fs implied=%.1f Mbit/s (524 = 50k×1310×8)",
		writes, fl, ratio, elapsed, impliedMbps)
}

// TestL3OverlayLoopOutDoesNotSyncRelayHostEgress verifies usque parity: LoopOut WritePacket
// does not read tun egress (LoopIn owns ReadHostEgress; sync relay deadlocks on readAccess).
func TestL3OverlayLoopOutDoesNotSyncRelayHostEgress(t *testing.T) {
	tunHost := netip.MustParseAddr("172.19.100.2")
	wireLocal := netip.MustParseAddr("198.18.0.1")
	server := netip.MustParseAddr("172.30.99.2")
	prefixes := []netip.Prefix{netip.MustParsePrefix(server.String() + "/32")}
	paramsTail := makeIPv4TCPPayload(tunHost, server, 40001, 5201, byte(header.TCPFlagAck|header.TCPFlagPsh), make([]byte, 52))

	var hostQ [][]byte
	hostRead := HostEgressReader(func(ctx context.Context, buf []byte) (int, error) {
		if len(hostQ) == 0 {
			if ctx.Err() != nil {
				return 0, nil
			}
			<-ctx.Done()
			return 0, ctx.Err()
		}
		pkt := hostQ[0]
		hostQ = hostQ[1:]
		return copy(buf, pkt), nil
	})

	w := &mockL3Writer{}
	b := NewL3OverlayBridge(func(p []byte) (int, error) {
		return len(p), nil
	}, w, &mockL3Reader{}, OverlayNAT{TunHost: tunHost, WireLocal: wireLocal})
	b.SetHostEgressRead(hostRead, prefixes)

	hostQ = append(hostQ, paramsTail)
	bulk := makeIPv4TCPPayload(server, wireLocal, 5201, 40001, 0x18, make([]byte, 1000))
	if err := b.WritePacket(bulk); err != nil {
		t.Fatalf("WritePacket bulk: %v", err)
	}
	if w.writes.Load() != 0 {
		t.Fatalf("writes=%d want 0 (LoopOut must not sync-relay host egress)", w.writes.Load())
	}
	buf := make([]byte, 2048)
	n, err := b.ReadPacket(context.Background(), buf)
	if err != nil || n <= 0 {
		t.Fatalf("LoopIn ReadPacket: n=%d err=%v", n, err)
	}
	if src, ok := ipv4Source(buf[:n]); !ok || src != wireLocal {
		t.Fatalf("LoopIn wire src=%v want SNAT %v", src, wireLocal)
	}
}

func TestL3OverlaySendClosed(t *testing.T) {
	b := NewL3OverlayBridge(nil, &mockL3Writer{}, nil, OverlayNAT{})
	b.Close()
	if err := b.Send([]byte{0x45}); err != net.ErrClosed {
		t.Fatalf("closed Send err=%v want ErrClosed", err)
	}
}

type mockL3Reader struct {
	packets [][]byte
	calls   atomic.Int32
}

func (m *mockL3Reader) ReadPacket(ctx context.Context, buf []byte) (int, error) {
	call := int(m.calls.Add(1))
	if call > len(m.packets) {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		<-ctx.Done()
		return 0, ctx.Err()
	}
	pkt := m.packets[call-1]
	copy(buf, pkt)
	return len(pkt), nil
}

func TestL3OverlayReceiveBatchDrain(t *testing.T) {
	pkt := []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 0, 0, 0, 127, 0, 0, 1, 127, 0, 0, 2}
	reader := &mockL3Reader{packets: [][]byte{pkt, pkt, pkt}}
	var injected atomic.Int32
	b := NewL3OverlayBridge(func(p []byte) (int, error) {
		injected.Add(1)
		return len(p), nil
	}, nil, reader, OverlayNAT{})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- b.RunPump(ctx)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for injected.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done

	if injected.Load() != 3 {
		t.Fatalf("injected=%d want 3 (batch drain pulls extra datagrams per iter)", injected.Load())
	}
	if reader.calls.Load() < 3 {
		t.Fatalf("reader calls=%d want >= 3", reader.calls.Load())
	}
}

func TestL3OverlayIngressWakeNote(t *testing.T) {
	pkt := []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 0, 0, 0, 127, 0, 0, 1, 127, 0, 0, 2}
	reader := &mockL3Reader{packets: [][]byte{pkt}}
	var noted atomic.Int32
	b := NewL3OverlayBridge(func(p []byte) (int, error) {
		return len(p), nil
	}, nil, reader, OverlayNAT{})
	b.SetIngressWakeNote(func([]byte) {
		noted.Add(1)
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- b.RunPump(ctx)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for noted.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done

	if noted.Load() != 1 {
		t.Fatalf("noted=%d want 1 per injected ingress packet", noted.Load())
	}
}

func TestL3OverlayIngressPayloadWake(t *testing.T) {
	pkt := make([]byte, 44)
	pkt[0] = 0x45
	pkt[2] = 0
	pkt[3] = 44
	pkt[9] = 6
	copy(pkt[12:16], []byte{127, 0, 0, 2})
	copy(pkt[16:20], []byte{127, 0, 0, 1})
	pkt[32] = 0x50 // TCP data offset 5
	pkt[33] = 0x18 // PSH+ACK
	copy(pkt[40:44], []byte{1, 2, 3, 4})
	reader := &mockL3Reader{packets: [][]byte{pkt}}
	var wakes atomic.Int32
	b := NewL3OverlayBridge(func(p []byte) (int, error) {
		return len(p), nil
	}, nil, reader, OverlayNAT{})
	b.SetIngressAckWakeHook(func() {
		wakes.Add(1)
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- b.RunPump(ctx)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for wakes.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done

	if wakes.Load() < 1 {
		t.Fatalf("wakes=%d want >= 1 (unified LoopOut batch-end wake)", wakes.Load())
	}
}

// TestL3HostKernelIngressPayloadWake (IP-DP-1) host-kernel LoopOut schedules ingress ACK wake.
func TestL3HostKernelIngressPayloadWake(t *testing.T) {
	pkt := make([]byte, 44)
	pkt[0] = 0x45
	pkt[2] = 0
	pkt[3] = 44
	pkt[9] = 6
	copy(pkt[12:16], []byte{127, 0, 0, 2})
	copy(pkt[16:20], []byte{127, 0, 0, 1})
	pkt[32] = 0x50
	pkt[33] = 0x18
	copy(pkt[40:44], []byte{1, 2, 3, 4})
	reader := &mockL3Reader{packets: [][]byte{pkt}}
	var wakes atomic.Int32
	b := NewL3OverlayBridge(func(p []byte) (int, error) {
		return len(p), nil
	}, nil, reader, OverlayNAT{})
	b.SetHostEgressRead(func(context.Context, []byte) (int, error) { return 0, nil }, nil)
	b.SetIngressAckWakeHook(func() {
		wakes.Add(1)
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- b.RunPump(ctx)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for wakes.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done

	if wakes.Load() < 1 {
		t.Fatalf("wakes=%d want >= 1 (host-kernel LoopOut batch-end wake)", wakes.Load())
	}
}

func TestL3OverlayHostTunWriteExcludesStackInject(t *testing.T) {
	pkt := make([]byte, 44)
	pkt[0] = 0x45
	pkt[2] = 0
	pkt[3] = 44
	pkt[9] = 6
	copy(pkt[12:16], []byte{127, 0, 0, 2})
	copy(pkt[16:20], []byte{127, 0, 0, 1})
	pkt[32] = 0x50
	copy(pkt[40:44], []byte{1, 2, 3, 4})
	reader := &mockL3Reader{packets: [][]byte{pkt}}
	var tunWrites atomic.Int32
	var stackInjects atomic.Int32
	b := NewL3OverlayBridge(func(p []byte) (int, error) {
		tunWrites.Add(1)
		return len(p), nil
	}, nil, reader, OverlayNAT{})
	b.SetStackIngressInject(func([]byte) error {
		stackInjects.Add(1)
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- b.RunPump(ctx)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for tunWrites.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done

	if tunWrites.Load() != 1 {
		t.Fatalf("tunWrites=%d want 1 (host kernel path)", tunWrites.Load())
	}
	if stackInjects.Load() != 0 {
		t.Fatalf("stackInjects=%d want 0 when tunWrite wired (no orphan netstack RST)", stackInjects.Load())
	}
}

func TestL3OverlayStackIngressInjectOnly(t *testing.T) {
	pkt := make([]byte, 44)
	pkt[0] = 0x45
	pkt[2] = 0
	pkt[3] = 44
	pkt[9] = 6
	copy(pkt[12:16], []byte{127, 0, 0, 2})
	copy(pkt[16:20], []byte{127, 0, 0, 1})
	pkt[32] = 0x50
	copy(pkt[40:44], []byte{1, 2, 3, 4})
	reader := &mockL3Reader{packets: [][]byte{pkt}}
	var stackInjects atomic.Int32
	b := NewL3OverlayBridge(nil, nil, reader, OverlayNAT{})
	b.SetStackIngressInject(func([]byte) error {
		stackInjects.Add(1)
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- b.RunPump(ctx)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for stackInjects.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done

	if stackInjects.Load() != 1 {
		t.Fatalf("stackInjects=%d want 1 without tunWrite", stackInjects.Load())
	}
}

func TestL3OverlayStackIngressHandshakeUsesTun(t *testing.T) {
	pkt := make([]byte, 40)
	pkt[0] = 0x45
	pkt[2] = 0
	pkt[3] = 40
	pkt[9] = 6
	copy(pkt[12:16], []byte{127, 0, 0, 1})
	copy(pkt[16:20], []byte{127, 0, 0, 2})
	pkt[32] = 0x50 // TCP header only, no payload
	reader := &mockL3Reader{packets: [][]byte{pkt}}
	var tunWrites atomic.Int32
	var stackInjects atomic.Int32
	b := NewL3OverlayBridge(func(p []byte) (int, error) {
		tunWrites.Add(1)
		return len(p), nil
	}, nil, reader, OverlayNAT{})
	b.SetStackIngressInject(func([]byte) error {
		stackInjects.Add(1)
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- b.RunPump(ctx)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for tunWrites.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done

	if tunWrites.Load() != 1 {
		t.Fatalf("tunWrites=%d want 1 for handshake (no payload)", tunWrites.Load())
	}
	if stackInjects.Load() != 0 {
		t.Fatalf("stackInjects=%d want 0 for handshake when tunWrite wired", stackInjects.Load())
	}
}

func TestL3OverlayWireIngressDNATToTunHost(t *testing.T) {
	tunHost := netip.MustParseAddr("172.19.100.2")
	wireLocal := netip.MustParseAddr("198.18.0.1")
	server := netip.MustParseAddr("172.30.99.2")
	payload := make([]byte, 53)
	pkt := make([]byte, 40+len(payload))
	pkt[0] = 0x45
	pkt[2] = 0
	pkt[3] = byte(len(pkt) >> 8)
	pkt[4] = byte(len(pkt))
	pkt[9] = 6
	copy(pkt[12:16], server.AsSlice())
	copy(pkt[16:20], wireLocal.AsSlice())
	pkt[32] = 0x50
	pkt[33] = 0x18
	copy(pkt[40:], payload)

	var tunOut []byte
	b := NewL3OverlayBridge(func(p []byte) (int, error) {
		tunOut = append([]byte(nil), p...)
		return len(p), nil
	}, &mockL3Writer{}, &mockL3Reader{}, OverlayNAT{TunHost: tunHost, WireLocal: wireLocal})
	b.SetStackIngressInject(func([]byte) error {
		t.Fatal("stackInject must not run on prod tunWrite path")
		return nil
	})

	if _, err := b.injectIngress(pkt); err != nil {
		t.Fatalf("injectIngress: %v", err)
	}
	if len(tunOut) == 0 {
		t.Fatal("wire ingress did not reach tunWrite")
	}
	dst, ok := ipv4Destination(tunOut)
	if !ok || dst != tunHost {
		t.Fatalf("tunWrite dst=%v ok=%v want %v", dst, ok, tunHost)
	}
	if !validIPv4TCPChecksum(tunOut) {
		t.Fatal("53B iperf reply tunWrite: invalid TCP checksum after DNAT")
	}
}

func TestL3OverlayWireIngressBulk1420ToTunHost(t *testing.T) {
	tunHost := netip.MustParseAddr("172.19.100.2")
	wireLocal := netip.MustParseAddr("198.18.0.1")
	server := netip.MustParseAddr("172.30.99.2")
	payload := make([]byte, 1380)
	for i := range payload {
		payload[i] = byte(i)
	}
	pkt := fwd.BuildIPv4TCPPacket(
		tcpip.AddrFrom4(server.As4()),
		tcpip.AddrFrom4(wireLocal.As4()),
		5201, 40000,
		1000, 2000,
		header.TCPFlagPsh|header.TCPFlagAck,
		65535, payload, nil,
	)
	nat := OverlayNAT{TunHost: tunHost, WireLocal: wireLocal}
	pkt = nat.DNATIngress(pkt)

	var tunOut []byte
	b := NewL3OverlayBridge(func(p []byte) (int, error) {
		tunOut = append([]byte(nil), p...)
		return len(p), nil
	}, &mockL3Writer{}, &mockL3Reader{}, nat)

	if _, err := b.injectIngress(pkt); err != nil {
		t.Fatalf("injectIngress bulk: %v", err)
	}
	if len(tunOut) < 1400 {
		t.Fatalf("tunWrite bulk len=%d want >= 1400", len(tunOut))
	}
	if !validIPv4TCPChecksum(tunOut) {
		t.Fatal("bulk tunWrite: invalid TCP checksum after DNAT")
	}
}

func TestL3BridgePumpLoopInUsesInPlaceNoWakeBatchFlush(t *testing.T) {
	w := &mockL3Writer{}
	reader := &mockL3Reader{}
	b := NewL3OverlayBridge(nil, w, reader, OverlayNAT{})
	b.SetStackIngressInject(func([]byte) error { return nil })
	b.SetPumpWakeHooks(cippump.WakeHooks{}, func() { w.FlushEgressBatch() })

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() { _ = b.RunPump(ctx) }()

	reader.packets = [][]byte{{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 0, 0, 0, 127, 0, 0, 1, 127, 0, 0, 2}}
	if err := b.Send([]byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	deadline := time.Now().Add(1500 * time.Millisecond)
	for w.inPlace.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if w.inPlace.Load() < 1 {
		t.Fatalf("inPlace=%d want >=1 (LoopIn must use in-place/no-wake wire path)", w.inPlace.Load())
	}
	if w.writes.Load() != 0 {
		t.Fatalf("WritePacket=%d want 0 (no per-packet flush path)", w.writes.Load())
	}
	if w.flushes.Load() < 1 {
		t.Fatalf("FlushEgressBatch=%d want >=1 via OnLoopInEnd", w.flushes.Load())
	}
}

func TestL3BridgePumpRestartAfterCancel(t *testing.T) {
	w := &mockL3Writer{}
	reader := &mockL3Reader{}
	b := NewL3OverlayBridge(nil, w, reader, OverlayNAT{})
	b.SetStackIngressInject(func([]byte) error { return nil })
	b.SetPumpWakeHooks(cippump.WakeHooks{}, func() { w.FlushEgressBatch() })

	ctx1, cancel1 := context.WithCancel(context.Background())
	done1 := make(chan error, 1)
	go func() { done1 <- b.RunPump(ctx1) }()

	pkt := []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 0, 0, 0, 127, 0, 0, 1, 127, 0, 0, 2}
	reader.packets = [][]byte{pkt}
	deadline := time.Now().Add(2 * time.Second)
	for w.inPlace.Load()+w.noWakeWrites.Load() < 1 && time.Now().Before(deadline) {
		if err := b.Send([]byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8}); err != nil {
			t.Fatalf("Send before cancel: %v", err)
		}
		time.Sleep(time.Millisecond)
	}
	cancel1()
	<-done1

	if err := b.Send([]byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8}); err != nil {
		t.Fatalf("Send after pump cancel: %v (bridge must stay alive for RestartIngress)", err)
	}

	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	done2 := make(chan error, 1)
	go func() { done2 <- b.RunPump(ctx2) }()

	before := w.inPlace.Load() + w.noWakeWrites.Load()
	if err := b.Send([]byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 0, 0, 0, 9, 9, 9, 9, 8, 8, 8, 8}); err != nil {
		t.Fatalf("Send after restart: %v", err)
	}
	deadline = time.Now().Add(2 * time.Second)
	for w.inPlace.Load()+w.noWakeWrites.Load() <= before && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel2()
	<-done2

	if w.inPlace.Load()+w.noWakeWrites.Load() <= before {
		t.Fatalf("LoopIn did not drain after pump restart")
	}
}

func TestL3WireDownloadDNATToTunWrite(t *testing.T) {
	tunHost := netip.MustParseAddr("172.19.100.2")
	wireLocal := netip.MustParseAddr("198.18.0.1")
	nat := OverlayNAT{TunHost: tunHost, WireLocal: wireLocal}
	var tunWritten atomic.Int32
	var lastPkt []byte
	b := NewL3OverlayBridge(func(p []byte) (int, error) {
		tunWritten.Add(1)
		lastPkt = append([]byte(nil), p...)
		return len(p), nil
	}, nil, nil, nat)

	// Server DATA on wire: dst=wireLocal, src=172.30.99.2
	pkt := make([]byte, 44)
	pkt[0] = 0x45
	pkt[2] = 0
	pkt[3] = 44
	pkt[9] = 6
	copy(pkt[12:16], []byte{172, 30, 99, 2})
	w4 := wireLocal.As4()
	copy(pkt[16:20], w4[:])
	pkt[32] = 0x50
	copy(pkt[40:44], []byte{1, 2, 3, 4})

	if err := b.WritePacket(pkt); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}
	if tunWritten.Load() != 1 {
		t.Fatalf("tunWrites=%d want 1", tunWritten.Load())
	}
	dst := netip.AddrFrom4([4]byte{lastPkt[16], lastPkt[17], lastPkt[18], lastPkt[19]})
	if dst != tunHost {
		t.Fatalf("DNAT dst=%v want tunHost %v", dst, tunHost)
	}
}

func TestL3WireDownloadBulkPayloadDNATToTunWrite(t *testing.T) {
	tunHost := netip.MustParseAddr("172.19.100.2")
	wireLocal := netip.MustParseAddr("198.18.0.1")
	server := netip.MustParseAddr("172.30.99.2")
	nat := OverlayNAT{TunHost: tunHost, WireLocal: wireLocal}
	payload := make([]byte, 1380)
	for i := range payload {
		payload[i] = byte(i)
	}
	dataPkt := makeIPv4TCPPayload(server, wireLocal, 5201, 40000, 0x18, payload)
	var tunWritten atomic.Int32
	var lastLen int
	b := NewL3OverlayBridge(func(p []byte) (int, error) {
		tunWritten.Add(1)
		lastLen = len(p)
		return len(p), nil
	}, nil, nil, nat)
	if err := b.WritePacket(dataPkt); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}
	if tunWritten.Load() != 1 {
		t.Fatalf("tunWrites=%d want 1", tunWritten.Load())
	}
	if lastLen < 1400 {
		t.Fatalf("bulk inject len=%d want >= 1400 (iperf segment parity)", lastLen)
	}
}

// TestL3WireDownloadHostACKReturnsOnWire simulates download: wire DATA → tunWrite → host ACK → l3Send → wire.
func TestL3WireDownloadHostACKReturnsOnWire(t *testing.T) {
	tunHost := netip.MustParseAddr("172.19.100.2")
	wireLocal := netip.MustParseAddr("198.18.0.1")
	server := netip.MustParseAddr("172.30.99.2")
	nat := OverlayNAT{TunHost: tunHost, WireLocal: wireLocal}

	w := &mockL3Writer{}
	dataPkt := makeIPv4TCPPayload(server, wireLocal, 5201, 40000, 0x18, []byte{1, 2, 3, 4})
	reader := &mockL3Reader{packets: [][]byte{dataPkt}}

	var bridge *L3OverlayBridge
	bridge = NewL3OverlayBridge(func(p []byte) (int, error) {
		ack := fwd.BuildIPv4TCPPacket(
			tcpip.AddrFrom4(tunHost.As4()),
			tcpip.AddrFrom4(server.As4()),
			40000, 5201,
			1000, 2000,
			header.TCPFlagAck,
			65535, nil, nil,
		)
		go func() { _ = bridge.Send(ack) }()
		return len(p), nil
	}, w, reader, nat)
	bridge.SetPumpWakeHooks(cippump.WakeHooks{}, func() { w.FlushEgressBatch() })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- bridge.RunPump(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for w.wireWrites() < 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done

	if w.wireWrites() < 1 {
		t.Fatalf("wire ACK wireWrites=%d want >= 1 (host tun read → Send → LoopIn)", w.wireWrites())
	}
	if pkt := w.lastPacket(); len(pkt) > 0 && !validIPv4TCPChecksum(pkt) {
		t.Fatalf("wire ACK len=%d: invalid TCP checksum after SNAT", len(pkt))
	}
	if w.flushes.Load() < 1 {
		t.Fatalf("flushes=%d want >= 1 after LoopIn batch", w.flushes.Load())
	}
}

// TestL3BulkUploadFINThenEgressAlive verifies bulk upload FIN does not stop LoopIn (post-upload download gate).
func TestL3BulkUploadFINThenEgressAlive(t *testing.T) {
	tunHost := netip.MustParseAddr("172.19.100.2")
	server := netip.MustParseAddr("172.30.99.2")

	w := &mockL3Writer{}
	reader := &mockL3Reader{}
	bridge := NewL3OverlayBridge(nil, w, reader, OverlayNAT{})
	bridge.SetStackIngressInject(func([]byte) error { return nil })
	bridge.SetPumpWakeHooks(cippump.WakeHooks{}, func() { w.FlushEgressBatch() })

	var hookEgress uint64
	bridge.SetShortFlowHook(func(_ netip.AddrPort, egressBytes uint64) {
		hookEgress = egressBytes
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- bridge.RunPump(ctx) }()

	const bulkPktLen = 1200
	for i := 0; i < (L3BulkFlowEgressThreshold/bulkPktLen)+1; i++ {
		pkt := make([]byte, bulkPktLen)
		pkt[0] = 0x45
		pkt[9] = 6
		if err := bridge.Send(pkt); err != nil {
			t.Fatalf("bulk Send[%d]: %v", i, err)
		}
	}
	fin := makeIPv4TCPFin(tunHost, server, 40000, 5201)
	if err := bridge.Send(fin); err != nil {
		t.Fatalf("FIN Send: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for hookEgress == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if hookEgress < L3BulkFlowEgressThreshold {
		t.Fatalf("shortFlowHook egressBytes=%d want >= %d (bulk upload leg)", hookEgress, L3BulkFlowEgressThreshold)
	}

	before := w.wireWrites()
	post := makeIPv4TCPAck(tunHost, server, 40001, 5201, 0x10)
	if err := bridge.Send(post); err != nil {
		t.Fatalf("post-FIN Send: %v", err)
	}
	for w.wireWrites() <= before && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done

	if w.wireWrites() <= before {
		t.Fatalf("post-FIN egress wireWrites=%d did not increase (before=%d); pump dead after bulk FIN", w.wireWrites(), before)
	}
}

func makeIPv4TCPPayload(src, dst netip.Addr, srcPort, dstPort uint16, tcpFlags byte, payload []byte) []byte {
	ihl := 20
	tcpLen := 20 + len(payload)
	total := ihl + tcpLen
	pkt := make([]byte, total)
	pkt[0] = 0x45
	pkt[2] = byte(total >> 8)
	pkt[3] = byte(total)
	pkt[9] = 6
	src4 := src.As4()
	dst4 := dst.As4()
	copy(pkt[12:16], src4[:])
	copy(pkt[16:20], dst4[:])
	pkt[ihl] = 0x50
	pkt[ihl+2] = byte(srcPort >> 8)
	pkt[ihl+3] = byte(srcPort)
	pkt[ihl+4] = byte(dstPort >> 8)
	pkt[ihl+5] = byte(dstPort)
	pkt[ihl+12] = 0x50 // data offset 5 (20 bytes)
	pkt[ihl+13] = tcpFlags
	copy(pkt[ihl+20:], payload)
	return pkt
}

func makeIPv4TCPAck(src, dst netip.Addr, srcPort, dstPort uint16, tcpFlags byte) []byte {
	return makeIPv4TCPPayload(src, dst, srcPort, dstPort, tcpFlags, nil)
}

func makeIPv4TCPFin(src, dst netip.Addr, srcPort, dstPort uint16) []byte {
	return makeIPv4TCPPayload(src, dst, srcPort, dstPort, 0x11, nil) // FIN+ACK
}

func makeIPv4TCPRst(src, dst netip.Addr, srcPort, dstPort uint16) []byte {
	return makeIPv4TCPPayload(src, dst, srcPort, dstPort, byte(header.TCPFlagRst), nil)
}

// TestL3BulkUploadRSTThenEgressAlive is G3/P3-5: explicit RST uses the same ShortFlowHook path as FIN.
func TestL3BulkUploadRSTThenEgressAlive(t *testing.T) {
	tunHost := netip.MustParseAddr("172.19.100.2")
	server := netip.MustParseAddr("172.30.99.2")

	w := &mockL3Writer{}
	reader := &mockL3Reader{}
	bridge := NewL3OverlayBridge(nil, w, reader, OverlayNAT{})
	bridge.SetStackIngressInject(func([]byte) error { return nil })
	bridge.SetPumpWakeHooks(cippump.WakeHooks{}, func() { w.FlushEgressBatch() })

	var hookEgress uint64
	bridge.SetShortFlowHook(func(_ netip.AddrPort, egressBytes uint64) {
		hookEgress = egressBytes
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- bridge.RunPump(ctx) }()

	const bulkPktLen = 1200
	for i := 0; i < (L3BulkFlowEgressThreshold/bulkPktLen)+1; i++ {
		pkt := make([]byte, bulkPktLen)
		pkt[0] = 0x45
		pkt[9] = 6
		if err := bridge.Send(pkt); err != nil {
			t.Fatalf("bulk Send[%d]: %v", i, err)
		}
	}
	rst := makeIPv4TCPRst(tunHost, server, 40000, 5201)
	if err := bridge.Send(rst); err != nil {
		t.Fatalf("RST Send: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for hookEgress == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if hookEgress < L3BulkFlowEgressThreshold {
		t.Fatalf("shortFlowHook egressBytes=%d want >= %d after RST", hookEgress, L3BulkFlowEgressThreshold)
	}

	before := w.wireWrites()
	post := makeIPv4TCPAck(tunHost, server, 40001, 5201, 0x10)
	if err := bridge.Send(post); err != nil {
		t.Fatalf("post-RST Send: %v", err)
	}
	for w.wireWrites() <= before && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done

	if w.wireWrites() <= before {
		t.Fatalf("post-RST egress wireWrites=%d did not increase (before=%d)", w.wireWrites(), before)
	}
}

func TestL3OverlayIngressPureAckWake(t *testing.T) {
	pkt := makeIPv4TCPAck(
		netip.MustParseAddr("172.30.99.2"),
		netip.MustParseAddr("198.18.0.1"),
		5201, 40000,
		0x10,
	)
	reader := &mockL3Reader{packets: [][]byte{pkt}}
	var wakes atomic.Int32
	b := NewL3OverlayBridge(func(p []byte) (int, error) {
		return len(p), nil
	}, nil, reader, OverlayNAT{
		TunHost:   netip.MustParseAddr("172.19.100.2"),
		WireLocal: netip.MustParseAddr("198.18.0.1"),
	})
	b.SetIngressAckWakeHook(func() {
		wakes.Add(1)
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- b.RunPump(ctx)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for wakes.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done

	if wakes.Load() < 1 {
		t.Fatalf("wakes=%d want >= 1 after pure ACK inject (iperf -R ACK path)", wakes.Load())
	}
}

// TestL3OverlayHostTunWriteServerAckDNAT verifies wire S2C server ACK → DNAT → tunWrite (host kernel path, no stackInject).
func TestL3OverlayHostTunWriteServerAckDNAT(t *testing.T) {
	tunHost := netip.MustParseAddr("172.19.100.2")
	wireLocal := netip.MustParseAddr("198.18.0.1")
	server := netip.MustParseAddr("172.30.99.2")
	tsOpt := []byte{
		header.TCPOptionNOP, header.TCPOptionNOP,
		header.TCPOptionTS, header.TCPOptionTSLength,
		0, 0, 0, 1, 0, 0, 0, 2,
	}
	ack := fwd.BuildIPv4TCPPacket(
		tcpip.AddrFrom4(server.As4()),
		tcpip.AddrFrom4(wireLocal.As4()),
		5201, 40000,
		2000, 1089,
		header.TCPFlagAck, 65535, nil, tsOpt,
	)
	reader := &mockL3Reader{packets: [][]byte{ack}}
	var tunWritten atomic.Bool
	b := NewL3OverlayBridge(func(p []byte) (int, error) {
		tunWritten.Store(true)
		if dst, ok := ipv4Destination(p); !ok || dst != tunHost {
			t.Errorf("tunWrite dst=%v want %v", dst, tunHost)
		}
		if !validIPv4TCPChecksum(p) {
			t.Errorf("tunWrite ACK len=%d: invalid TCP checksum after DNAT", len(p))
		}
		return len(p), nil
	}, nil, reader, OverlayNAT{TunHost: tunHost, WireLocal: wireLocal})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- b.RunPump(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for !tunWritten.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done

	if !tunWritten.Load() {
		t.Fatal("no tunWrite after server ACK ingress (upload 89B retransmit analog)")
	}
}

func TestL3OverlayReceiveBatchWake(t *testing.T) {
	pkt := []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 0, 0, 0, 127, 0, 0, 1, 127, 0, 0, 2}
	reader := &mockL3Reader{packets: [][]byte{pkt}}
	var wakes atomic.Int32
	b := NewL3OverlayBridge(func(p []byte) (int, error) {
		return len(p), nil
	}, nil, reader, OverlayNAT{})
	b.SetIngressAckWakeHook(func() {
		wakes.Add(1)
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- b.RunPump(ctx)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for wakes.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done

	if wakes.Load() < 1 {
		t.Fatalf("wakes=%d want >= 1 per LoopOut batch (unified wake)", wakes.Load())
	}
}
