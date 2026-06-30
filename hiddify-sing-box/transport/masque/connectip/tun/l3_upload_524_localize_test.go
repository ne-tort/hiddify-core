package tun

import (
	"context"
	"net/netip"
	"runtime"
	"testing"
	"time"

	cippump "github.com/sagernet/sing-box/transport/masque/connectip/pump"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
)

type upload524PumpHarnessOpts struct {
	LoopInUsqueImmediate bool
	Prod                 bool // prod usquePumpOptions via RunPump
	NoObserver           bool // skip LoopInObserver overhead in tight budget gates
}

func makeUpload524BulkSeg(t *testing.T) []byte {
	t.Helper()
	tunHost := netip.MustParseAddr("172.19.100.2")
	server := netip.MustParseAddr("198.18.0.99")
	payload := make([]byte, Upload524SegBytes-20-20-20)
	bulk := makeIPv4TCPPayload(tunHost, server, 40000, 5201, byte(header.TCPFlagAck|header.TCPFlagPsh), payload)
	if len(bulk) < 1200 {
		t.Fatalf("bulk len=%d want MSS-ish", len(bulk))
	}
	return bulk
}

func runHostKernelPumpMeter(t *testing.T, host HostEgressReader, w *mockL3Writer, runFor time.Duration, harness upload524PumpHarnessOpts) upload524PumpMeter {
	t.Helper()
	tunHost := netip.MustParseAddr("172.19.100.2")
	wireLocal := netip.MustParseAddr("198.18.0.1")
	server := netip.MustParseAddr("198.18.0.99")
	prefixes := []netip.Prefix{netip.MustParsePrefix(server.String() + "/32")}

	b := NewL3OverlayBridge(func(p []byte) (int, error) { return len(p), nil }, w, &mockL3Reader{}, OverlayNAT{
		TunHost: tunHost, WireLocal: wireLocal,
	})
	b.SetHostEgressRead(host, prefixes)
	onFlush := func() { w.FlushEgressBatch() }
	b.SetPumpWakeHooks(cippump.WakeHooks{}, onFlush)

	opts := b.usquePumpOptions(onFlush)
	if b.hostKernelRelay() {
		opts.OnLoopInEnd = onFlush
	}
	if !harness.Prod {
		opts.LoopInUsqueImmediate = harness.LoopInUsqueImmediate
	}

	loopObs := &cippump.LoopInObserver{}
	hostReadObs := &HostKernelReadObserver{}
	if !harness.NoObserver {
		opts.LoopInObserver = loopObs
	}

	ctx, cancel := context.WithCancel(context.Background())
	start := time.Now()
	go func() {
		device := b.tunnelDevice()
		if device == nil {
			return
		}
		if kd, ok := device.(*KernelTunDevice); ok && !harness.NoObserver {
			kd.AttachReadObserver(hostReadObs)
		}
		if harness.Prod {
			_ = b.RunPump(ctx)
			return
		}
		_ = cippump.RunTunnel(ctx, device, b.packetConn(), opts)
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
	m := upload524PumpMeter{
		Writes: writes, Flushes: fl, Elapsed: elapsed,
		PPS: pps, Mbps: mbps, PktsPerFlush: pf,
		LoopIn:   loopObs.Snapshot(),
		HostRead: hostReadObs.Snapshot(),
	}
	m.Bound = classifyUploadBound(m)
	return m
}

func assertUpload524Band(t *testing.T, label string, m upload524PumpMeter) {
	t.Helper()
	if m.PPS < Upload524PPSBandLo || m.PPS > Upload524PPSBandHi {
		t.Fatalf("%s: pps=%.0f want %d–%d (writes=%d elapsed=%v)",
			label, m.PPS, Upload524PPSBandLo, Upload524PPSBandHi, m.Writes, m.Elapsed)
	}
	if m.Mbps < Upload524MbpsBandLo || m.Mbps > Upload524MbpsBandHi {
		t.Fatalf("%s: mbps=%.1f want %.0f–%.0f", label, m.Mbps, Upload524MbpsBandLo, Upload524MbpsBandHi)
	}
	t.Logf("%s: writes=%d flushes=%d pps=%.0f mbps=%.1f pkts/flush=%.2f",
		label, m.Writes, m.Flushes, m.PPS, m.Mbps, m.PktsPerFlush)
}

func requireUpload524SubMsClock(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("LOCALIZE-UP rate repro needs Linux sub-ms clock (WSL/Docker); formula + fast-path still run on Windows")
	}
}

func logUploadBoundMetrics(t *testing.T, label string, m upload524PumpMeter) {
	t.Helper()
	t.Logf("%s: bound=%s writes=%d flushes=%d pps=%.0f mbps=%.1f pkts/flush=%.2f pkts/iter=%.2f read_us/pkt=%.1f write_us/pkt=%.1f host_accepted=%d",
		label, m.Bound, m.Writes, m.Flushes, m.PPS, m.Mbps, m.PktsPerFlush,
		m.LoopIn.PktsPerIter, m.LoopIn.ReadUsPerPkt, m.LoopIn.WriteUsPerPkt, m.HostRead.Accepted)
}

func upload524Max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
