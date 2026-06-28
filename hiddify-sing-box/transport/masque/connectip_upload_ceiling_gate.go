package masque

// Upload 524 Mbit/s ceiling localization (PERF-UP): 524 = 50_000 pps × 1310 B × 8.

import (
	"math"
	"sync/atomic"
	"testing"
	"time"
)

const (
	connectIPUploadCeilingMbps        = 524.0
	connectIPUploadCeilingSegBytes    = 1310
	connectIPUploadCeilingPPS         = 50000
	connectIPUploadCeilingFlushRatio  = 1.15 // pkts/flush ≈1 → flush-bound LoopIn
	connectIPUploadLocalizeMinBytes   = 32 * 1024
)

func connectIPUploadCeilingFromPPS(pps float64, segBytes int) float64 {
	if pps <= 0 || segBytes <= 0 {
		return 0
	}
	return pps * float64(segBytes) * 8 / 1e6
}

func gateConnectIPUpload524Formula(t *testing.T) {
	t.Helper()
	got := connectIPUploadCeilingFromPPS(connectIPUploadCeilingPPS, connectIPUploadCeilingSegBytes)
	if math.Abs(got-connectIPUploadCeilingMbps) > 0.05 {
		t.Fatalf("524 formula: %.3f Mbit/s want %.1f (pps=%d seg=%d B)",
			got, connectIPUploadCeilingMbps, connectIPUploadCeilingPPS, connectIPUploadCeilingSegBytes)
	}
	t.Logf("524 ceiling identity: %d pps × %d B = %.1f Mbit/s",
		connectIPUploadCeilingPPS, connectIPUploadCeilingSegBytes, got)
}

type wireMeterSession struct {
	IPPacketSession
	writes atomic.Int64
	bytes  atomic.Int64
}

func (w *wireMeterSession) WritePacket(p []byte) ([]byte, error) {
	w.writes.Add(1)
	w.bytes.Add(int64(len(p)))
	return w.IPPacketSession.WritePacket(p)
}

type hostEgressUploadMeter struct {
	h       *connectIPL3PumpHarness
	wire    *wireMeterSession
	flushes atomic.Int64
}

func startConnectIPL3HostEgressUploadMeter(t *testing.T, link packetLink) *hostEgressUploadMeter {
	t.Helper()
	rawClient, serverSess := link.endpoints()
	meter := &wireMeterSession{IPPacketSession: rawClient}
	m := &hostEgressUploadMeter{wire: meter}
	m.h = startConnectIPL3HostEgressHarnessWithClient(t, meter, serverSess, &m.flushes)
	return m
}

func gateConnectIPL3HostEgressUploadLocalize(t *testing.T) {
	t.Helper()
	const benchDur = 500 * time.Millisecond
	m := startConnectIPL3HostEgressUploadMeter(t, prodInstantPacketLink{})
	defer m.h.close()

	upConn := m.h.dialRemote(t)
	upBytes, upMbps, err := measureTCPUploadMbps(upConn, benchDur)
	_ = upConn.Close()
	if err != nil && upBytes == 0 {
		t.Fatalf("host-egress upload: %v", err)
	}
	if upBytes < connectIPUploadLocalizeMinBytes {
		t.Fatalf("host-egress upload=%d bytes want >= %d (%.1f Mbit/s)", upBytes, connectIPUploadLocalizeMinBytes, upMbps)
	}

	writes := m.wire.writes.Load()
	flushes := m.flushes.Load()
	avgPkt := int64(0)
	if writes > 0 {
		avgPkt = m.wire.bytes.Load() / writes
	}
	secs := benchDur.Seconds()
	pps := float64(writes) / secs
	flushPPS := float64(flushes) / secs
	pktsPerFlush := float64(writes) / float64(max64(flushes, 1))
	impliedMbps := connectIPUploadCeilingFromPPS(pps, int(avgPkt))

	l1 := benchConnectIPUploadLayerBest(t, "L1-prod", prodInstantPacketLink{}, benchDur, 1)
	t.Logf("host-egress upload: %.1f Mbit/s (%d B) writes=%d flushes=%d avgPkt=%d pps=%.0f flushPPS=%.0f pkts/flush=%.2f implied=%.1f Mbit/s",
		upMbps, upBytes, writes, flushes, avgPkt, pps, flushPPS, pktsPerFlush, impliedMbps)
	t.Logf("L1-prod (no host read): %.1f Mbit/s ratio=%.2f", l1.mbps, safeRatio(upMbps, l1.mbps))

	if pktsPerFlush <= connectIPUploadCeilingFlushRatio {
		t.Logf("LOCALIZE flush-bound: pkts/flush=%.2f → ceiling ≈ flushPPS×avgSeg (524 @ %d B × 50k flush/s)",
			pktsPerFlush, connectIPUploadCeilingSegBytes)
	}
	if avgPkt >= 1200 && avgPkt <= 1420 && math.Abs(flushPPS-connectIPUploadCeilingPPS) < 15000 {
		t.Logf("LOCALIZE segment+flush rate matches Docker 524 identity (avgPkt=%d flushPPS=%.0f)", avgPkt, flushPPS)
	}
}

func safeRatio(a, b float64) float64 {
	if b <= 0 {
		return 0
	}
	return a / b
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
