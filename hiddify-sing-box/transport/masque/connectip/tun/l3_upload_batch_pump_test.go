package tun

import (
	"context"
	"net/netip"
	"testing"
	"time"

	cippump "github.com/sagernet/sing-box/transport/masque/connectip/pump"
)

// runHostKernelBatchPumpMeter runs RunTunnelBatch (upload DoD path) with host-kernel device.
func runHostKernelBatchPumpMeter(t *testing.T, host HostEgressReader, w *mockL3Writer, runFor time.Duration) upload524PumpMeter {
	t.Helper()
	tunHost := netip.MustParseAddr("172.19.100.2")
	wireLocal := netip.MustParseAddr("198.18.0.1")
	server := netip.MustParseAddr("198.18.0.99")
	prefixes := []netip.Prefix{netip.MustParsePrefix(server.String() + "/32")}

	kd := NewKernelTunDevice(host, func(p []byte) (int, error) { return len(p), nil },
		OverlayNAT{TunHost: tunHost, WireLocal: wireLocal}, prefixes, nil)
	if kd == nil {
		t.Fatal("NewKernelTunDevice nil")
	}

	b := NewL3OverlayBridge(func(p []byte) (int, error) { return len(p), nil }, w, &mockL3Reader{}, OverlayNAT{
		TunHost: tunHost, WireLocal: wireLocal,
	})
	onFlush := func() { w.FlushEgressBatch() }
	pc := b.packetConn()

	opts := cippump.TunnelOptions{
		NetBuffer:    cippump.NewNetBuffer(cippump.DefaultTunnelMTU),
		OnLoopInEnd:  onFlush,
		LoopInObserver: &cippump.LoopInObserver{},
	}
	hostReadObs := &HostKernelReadObserver{}
	kd.AttachReadObserver(hostReadObs)

	ctx, cancel := context.WithCancel(context.Background())
	start := time.Now()
	go func() {
		_ = cippump.RunTunnelBatch(ctx, kd, pc, opts, cippump.DefaultLoopInMaxBatch)
	}()
	time.Sleep(runFor)
	cancel()

	elapsed := time.Since(start)
	writes := int64(w.inPlace.Load() + w.noWakeWrites.Load())
	fl := int64(w.flushes.Load())
	pps := float64(writes) / elapsed.Seconds()
	avgSeg := Upload524SegBytes
	if writes > 0 && w.lastPacket() != nil {
		avgSeg = len(w.lastPacket())
	}
	mbps := upload524MbpsFromPPS(pps, avgSeg)
	pf := float64(writes) / float64(upload524Max64(fl, 1))
	loopObs := opts.LoopInObserver.Snapshot()
	m := upload524PumpMeter{
		Writes: writes, Flushes: fl, Elapsed: elapsed,
		PPS: pps, Mbps: mbps, PktsPerFlush: pf,
		LoopIn:   loopObs,
		HostRead: hostReadObs.Snapshot(),
	}
	m.Bound = classifyUploadBound(m)
	return m
}

// runHostKernelRunPumpMeter runs prod RunPump (RunTunnelBatch when host-kernel wired).
func runHostKernelRunPumpMeter(t *testing.T, host HostEgressReader, w *mockL3Writer, runFor time.Duration) upload524PumpMeter {
	t.Helper()
	return runHostKernelPumpMeter(t, host, w, runFor, upload524PumpHarnessOpts{Prod: true, NoObserver: true})
}
