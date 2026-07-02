package masque

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque/connectudp"
)

// Synth CPU gates: setup once, short timed sample, hard wall (no testing.Benchmark re-dial).
const (
	connectUDPCPUBenchIterBytes   = 64 * 1024  // bytes per timed iteration
	connectUDPCPUBenchGateBytes   = 256 * 1024 // total sample for ns/byte gate
	connectUDPCPUBenchGateWall    = 12 * time.Second
	connectUDPCPUBudgetMatrixWall = 50 * time.Second
)

// cpuBudgetNsPerByte converts bytes+nanos to ns/byte.
func cpuBudgetNsPerByte(totalBytes int64, totalNs int64) float64 {
	if totalBytes <= 0 || totalNs <= 0 {
		return 0
	}
	return float64(totalNs) / float64(totalBytes)
}

func logCPUBudgetLine(tb testing.TB, site, codeRef string, nsPerB, maxNsPerB float64, wall time.Duration) {
	tb.Helper()
	ceiling := synthCPUMbpsCeiling(nsPerB)
	maxCeiling := synthCPUMbpsCeiling(maxNsPerB)
	tb.Logf(
		"RESULT_CPU site=%s code=%q ns_per_b=%.1f max_ns_per_b=%.1f cpu_ceiling_mbps=%.0f budget_ceiling_mbps=%.0f wall=%v",
		site, codeRef, nsPerB, maxNsPerB, ceiling, maxCeiling, wall.Round(time.Millisecond),
	)
}

func assertCPUBudget(tb testing.TB, site string, nsPerB, maxNsPerB float64) {
	tb.Helper()
	if nsPerB <= maxNsPerB {
		return
	}
	tb.Fatalf("%s", synthKPIDiagnostic(site, "cpu_ns_per_b", nsPerB, maxNsPerB,
		fmt.Sprintf("CPU budget OPEN; implied ceiling %.0f Mbit/s", synthCPUMbpsCeiling(nsPerB))))
}

// measureCPUBudgetGate runs iter (fixed bytes) until gateBytes sampled or maxWall exceeded.
func measureCPUBudgetGate(tb testing.TB, site string, maxWall time.Duration, gateBytes int64, iter func() int64) (nsPerB float64, wall time.Duration) {
	tb.Helper()
	start := time.Now()
	deadline := start.Add(maxWall)

	// Untimed warmup (one iter).
	if n := iter(); n <= 0 {
		tb.Fatalf("CPU budget %s: warmup returned zero bytes", site)
	}

	var totalBytes int64
	sampleStart := time.Now()
	for totalBytes < gateBytes {
		if time.Now().After(deadline) {
			tb.Fatalf("CPU budget %s hung: wall>%v collected=%d bytes want>=%d", site, maxWall, totalBytes, gateBytes)
		}
		n := iter()
		if n <= 0 {
			tb.Fatalf("CPU budget %s: zero-byte timed iteration", site)
		}
		totalBytes += n
	}
	sampleNs := time.Since(sampleStart).Nanoseconds()
	wall = time.Since(start)
	if sampleNs <= 0 {
		sampleNs = wall.Nanoseconds()
	}
	if sampleNs <= 0 {
		sampleNs = 1
	}
	return cpuBudgetNsPerByte(totalBytes, sampleNs), wall
}

func benchConnectUDPCPUUploadN(tb testing.TB, pkt net.PacketConn, addr net.Addr, payload []byte, maxBytes int64) int64 {
	tb.Helper()
	var sent int64
	for sent < maxBytes {
		n, err := pkt.WriteTo(payload, addr)
		if err != nil {
			tb.Fatal(err)
		}
		sent += int64(n)
	}
	return sent
}

func benchConnectUDPCPUReceiveN(tb testing.TB, pkt net.PacketConn, buf []byte, maxBytes int64) int64 {
	tb.Helper()
	if len(buf) < connectudp.DefaultBenchUDPPayloadLen+64 {
		buf = make([]byte, connectudp.DefaultBenchUDPPayloadLen+64)
	}
	var received int64
	for received < maxBytes {
		n, _, err := pkt.ReadFrom(buf)
		if err != nil {
			tb.Fatal(err)
		}
		received += int64(n)
	}
	return received
}

func runCPUBudgetGate(tb testing.TB, site string, maxNsPerB float64, maxWall time.Duration, iter func() int64) {
	tb.Helper()
	if testing.Short() {
		tb.Skip("short")
	}
	nsPerB, wall := measureCPUBudgetGate(tb, site, maxWall, connectUDPCPUBenchGateBytes, iter)
	logCPUBudgetLine(tb, site, cpuSiteCodeRef[site], nsPerB, maxNsPerB, wall)
	assertCPUBudget(tb, site, nsPerB, maxNsPerB)
}
