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
	CoalescePoll         time.Duration // -1 = prod default (100µs host-kernel)
	LoopInUsqueImmediate bool
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
	if harness.CoalescePoll >= 0 {
		opts.LoopInCoalescePoll = harness.CoalescePoll
	}
	opts.LoopInUsqueImmediate = harness.LoopInUsqueImmediate

	loopObs := &cippump.LoopInObserver{}
	hostReadObs := &HostKernelReadObserver{}
	opts.LoopInObserver = loopObs

	ctx, cancel := context.WithCancel(context.Background())
	start := time.Now()
	go func() {
		device := b.tunnelDevice()
		if device == nil {
			return
		}
		if kd, ok := device.(*KernelTunDevice); ok {
			kd.AttachReadObserver(hostReadObs)
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

// TestGATEConnectIPUpload524ReproHostPaced (LOCALIZE-UP-1) depth-1 host @ 20µs/pkt → 524 Mbit/s identity.
func TestGATEConnectIPUpload524ReproHostPaced(t *testing.T) {
	requireUpload524SubMsClock(t)
	seg := makeUpload524BulkSeg(t)
	w := &mockL3Writer{}
	m := runHostKernelPumpMeter(t, hostEgressReadPaced(Upload524PktSpacing, seg), w, 600*time.Millisecond, upload524PumpHarnessOpts{
		CoalescePoll:         0,
		LoopInUsqueImmediate: true,
	})
	if m.Writes < 2000 {
		t.Fatalf("writes=%d want >=2000 for steady sample", m.Writes)
	}
	assertUpload524Band(t, "host-paced", m)
}

// TestGATEConnectIPUpload524ReproWirePaced (LOCALIZE-UP-2) instant host + 20µs wire → same 524 band.
func TestGATEConnectIPUpload524ReproWirePaced(t *testing.T) {
	requireUpload524SubMsClock(t)
	seg := makeUpload524BulkSeg(t)
	w := &mockL3Writer{inPlaceDelay: Upload524PktSpacing}
	m := runHostKernelPumpMeter(t, hostEgressInfinite(seg), w, 600*time.Millisecond, upload524PumpHarnessOpts{
		CoalescePoll:         0,
		LoopInUsqueImmediate: true,
	})
	if m.Writes < 2000 {
		t.Fatalf("writes=%d want >=2000", m.Writes)
	}
	assertUpload524Band(t, "wire-paced", m)
}

// TestGATEConnectIPUpload524DiscriminateFastPath (LOCALIZE-UP-3) no throttle → must exceed 524 band (not tun-limited).
func TestGATEConnectIPUpload524DiscriminateFastPath(t *testing.T) {
	seg := makeUpload524BulkSeg(t)
	w := &mockL3Writer{}
	m := runHostKernelPumpMeter(t, hostEgressInfinite(seg), w, 150*time.Millisecond, upload524PumpHarnessOpts{
		CoalescePoll:         0,
		LoopInUsqueImmediate: true,
	})
	if m.Writes < 500 {
		t.Fatalf("writes=%d want >=500", m.Writes)
	}
	if m.Mbps <= Upload524MbpsBandHi {
		t.Fatalf("fast path mbps=%.1f want > %.0f (proves 524 is throttle identity, not mock ceiling)",
			m.Mbps, Upload524MbpsBandHi)
	}
	if m.PPS <= float64(Upload524PPSBandHi) {
		t.Fatalf("fast path pps=%.0f want > %d", m.PPS, Upload524PPSBandHi)
	}
	t.Logf("fast path: writes=%d pps=%.0f mbps=%.1f pkts/flush=%.1f",
		m.Writes, m.PPS, m.Mbps, m.PktsPerFlush)
}

// TestGATEConnectIPUpload524CauseSummary logs the localization verdict (always pass — diagnostic gate).
func TestGATEConnectIPUpload524CauseSummary(t *testing.T) {
	got := upload524MbpsFromPPS(Upload524PPS, Upload524SegBytes)
	if got < Upload524MbpsBandLo || got > Upload524MbpsBandHi {
		t.Fatalf("formula mbps=%.1f want band", got)
	}
	t.Logf("LOCALIZE verdict: Docker 524 = %d pps × %d B = %.1f Mbit/s",
		Upload524PPS, Upload524SegBytes, got)
	t.Logf("LOCALIZE repro: pace host OR wire @ %v → same band (LOCALIZE-UP-1/2)", Upload524PktSpacing)
	t.Logf("LOCALIZE discriminate: unpaced pump >>524 (LOCALIZE-UP-3) → prod cap = iteration budget @ ~50 kpps")
	t.Logf("LOCALIZE prod mapping: kernel tun ReadHostEgress depth-1 ≈ %v/pkt (not slow QUIC on instant wire)", Upload524PktSpacing)
}

func upload524Max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
