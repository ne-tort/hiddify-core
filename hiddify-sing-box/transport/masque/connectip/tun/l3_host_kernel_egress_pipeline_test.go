package tun

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	cippump "github.com/sagernet/sing-box/transport/masque/connectip/pump"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
)

// slowFlushWriter adds latency on wire enqueue (localize LoopIn ‖ write overlap).
type slowFlushWriter struct {
	mockL3Writer
	delay time.Duration
}

func (s *slowFlushWriter) WritePacketInPlaceNoWake(p []byte) (retained bool, icmp []byte, err error) {
	if s.delay > 0 {
		time.Sleep(s.delay)
	}
	return s.mockL3Writer.WritePacketInPlaceNoWake(p)
}

// TestL3HostKernelEgressPipelineOverlap (GATE-UP-4) slow wire writer: pipeline completes host reads faster than sync path.
func TestL3HostKernelEgressPipelineOverlap(t *testing.T) {
	tunHost := netip.MustParseAddr("172.19.100.2")
	wireLocal := netip.MustParseAddr("198.18.0.1")
	server := netip.MustParseAddr("198.18.0.99")
	prefixes := []netip.Prefix{netip.MustParsePrefix(server.String() + "/32")}
	bulk := makeIPv4TCPPayload(tunHost, server, 40000, 5201, byte(header.TCPFlagAck|header.TCPFlagPsh), make([]byte, 512))

	const burst = 24
	const wireDelay = 25 * time.Microsecond

	runBurst := func(pipeline bool) (reads int32, wall time.Duration) {
		var readCount atomic.Int32
		hostRead := HostEgressReader(func(ctx context.Context, buf []byte) (int, error) {
			n := int(readCount.Add(1))
			if n > burst {
				<-ctx.Done()
				return 0, ctx.Err()
			}
			return copy(buf, bulk), nil
		})

		w := &slowFlushWriter{delay: wireDelay}
		b := NewL3OverlayBridge(func(p []byte) (int, error) { return len(p), nil }, w, &mockL3Reader{}, OverlayNAT{
			TunHost: tunHost, WireLocal: wireLocal,
		})
		b.SetHostEgressRead(hostRead, prefixes)
		b.SetPumpWakeHooks(cippump.WakeHooks{}, func() { w.FlushEgressBatch() })

		ctx, cancel := context.WithCancel(context.Background())
		start := time.Now()
		if pipeline {
			flushFn := func() { w.FlushEgressBatch() }
			pipe := newHostKernelEgressPipeline(ctx, w, flushFn, cippump.DefaultNetBuffer())
			pipe.start()
			b.mu.Lock()
			b.hostEgressPipe = pipe
			b.mu.Unlock()
			defer func() {
				pipe.stop()
				b.mu.Lock()
				b.hostEgressPipe = nil
				b.mu.Unlock()
			}()
			go func() {
				opts := b.usquePumpOptions(flushFn)
				opts.OnLoopInEnd = nil
				_ = cippump.RunTunnel(ctx, b.tunnelDevice(), b.packetConn(), opts)
			}()
		} else {
			go func() {
				opts := b.usquePumpOptions(func() { w.FlushEgressBatch() })
				_ = cippump.RunTunnel(ctx, b.tunnelDevice(), b.packetConn(), opts)
			}()
		}

		deadline := time.Now().Add(2 * time.Second)
		for readCount.Load() < burst && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		cancel()
		return readCount.Load(), time.Since(start)
	}

	syncReads, syncWall := runBurst(false)
	pipeReads, pipeWall := runBurst(true)
	if syncReads < burst || pipeReads < burst {
		t.Fatalf("burst incomplete sync=%d pipe=%d want %d", syncReads, pipeReads, burst)
	}
	if pipeWall >= syncWall {
		t.Fatalf("pipeline wall=%v want < sync=%v (overlap read‖write)", pipeWall, syncWall)
	}
	t.Logf("egress pipeline: sync=%v pipe=%v speedup=%.2fx", syncWall, pipeWall, float64(syncWall)/float64(pipeWall))
}
