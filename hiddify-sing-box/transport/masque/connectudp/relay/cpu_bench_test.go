package relay

import (
	"context"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	relayCPUBenchIterBytes     = 64 * 1024
	relayCPUBenchGateBytes     = 256 * 1024
	relayCPUBenchGateWall      = 8 * time.Second
	relayS2CBenchWriterBurst   = 32 // pre-fill socket RX queue for readOnwardUDPBatch coalesce
	relayS2CMaxNsPerB          = 80.0
	relayS2CMinPktsPerBatch    = 2.0
	relayS2CWindowsMaxNsPerB   = 500.0 // loopback UDP coalesce=1; syscall-heavy, not prod CPU
)

func relayPumpS2CBenchUDP(sink *net.UDPConn, payload []byte, relayAddr *net.UDPAddr, stop <-chan struct{}) {
	for {
		select {
		case <-stop:
			return
		default:
		}
		for range relayS2CBenchWriterBurst {
			if _, err := sink.WriteToUDP(payload, relayAddr); err != nil {
				return
			}
		}
	}
}

type relayS2CBenchSender struct {
	bytes atomic.Uint64
}

func (m *relayS2CBenchSender) SendDatagram(data []byte) error {
	m.bytes.Add(uint64(len(data)))
	return nil
}

type relayS2CBenchHarness struct {
	relayConn *net.UDPConn
	mock      *relayS2CBenchSender
	stop      chan struct{}
	writerWG  sync.WaitGroup
	recvDone  chan error
}

func startRelayS2CBenchHarness(t testing.TB) *relayS2CBenchHarness {
	t.Helper()
	payload := make([]byte, 512)
	sink, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sink.Close() })
	relayConn, err := net.DialUDP("udp", nil, sink.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	TuneMasqueUDPSocketBuffers(relayConn)

	h := &relayS2CBenchHarness{
		relayConn: relayConn,
		mock:      &relayS2CBenchSender{},
		stop:     make(chan struct{}),
		recvDone: make(chan error, 1),
	}
	relayAddr := relayConn.LocalAddr().(*net.UDPAddr)
	h.writerWG.Add(1)
	go func() {
		defer h.writerWG.Done()
		relayPumpS2CBenchUDP(sink, payload, relayAddr, h.stop)
	}()
	go func() {
		h.recvDone <- proxyConnReceive(context.Background(), relayConn, h.mock)
	}()
	return h
}

func (h *relayS2CBenchHarness) close() {
	close(h.stop)
	_ = h.relayConn.Close()
	h.writerWG.Wait()
	<-h.recvDone
}

func relayMeasureCPUBudget(t testing.TB, maxWall time.Duration, gateBytes int64, iter func(deadline time.Time) int64) float64 {
	t.Helper()
	start := time.Now()
	deadline := start.Add(maxWall)
	if n := iter(deadline); n <= 0 {
		t.Fatal("relay CPU warmup: zero bytes")
	}
	var totalBytes int64
	sampleStart := time.Now()
	for totalBytes < gateBytes {
		if time.Now().After(deadline) {
			t.Fatalf("relay S2C CPU hung: wall>%v collected=%d want>=%d", maxWall, totalBytes, gateBytes)
		}
		n := iter(deadline)
		if n <= 0 {
			t.Fatal("relay S2C CPU: zero-byte iteration")
		}
		totalBytes += n
	}
	sampleNs := time.Since(sampleStart).Nanoseconds()
	if sampleNs <= 0 {
		sampleNs = time.Since(start).Nanoseconds()
	}
	if sampleNs <= 0 {
		sampleNs = 1
	}
	if totalBytes <= 0 {
		t.Fatalf("relay S2C CPU: invalid sample bytes=%d", totalBytes)
	}
	return float64(sampleNs) / float64(totalBytes)
}

func relayWaitBytes(mock *relayS2CBenchSender, want int64, deadline time.Time) int64 {
	start := mock.bytes.Load()
	target := start + uint64(want)
	for mock.bytes.Load() < target {
		if time.Now().After(deadline) {
			got := int64(mock.bytes.Load() - start)
			if got <= 0 {
				return 0
			}
			return got
		}
	}
	return want
}

func relayS2CPktsPerBatch(s UDPRelayStatsSnapshot) float64 {
	return float64(s.S2CBatchPkts) / float64(relayMaxU64(s.S2CBatchReads, 1))
}

func relayS2CMaxNsPerBForHost() float64 {
	if runtime.GOOS == "windows" {
		return relayS2CWindowsMaxNsPerB
	}
	return relayS2CMaxNsPerB
}

// TestGATERelayS2CCPUBudget measures isolated relay S2C ns/byte (kernel-bound; not full MASQUE stack).
func TestGATERelayS2CCPUBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	maxNsPerB := relayS2CMaxNsPerBForHost()
	EnableRelayStatsForBench()
	ResetUDPRelayStats()
	h := startRelayS2CBenchHarness(t)
	defer h.close()
	wallStart := time.Now()
	nsPerB := relayMeasureCPUBudget(t, relayCPUBenchGateWall, relayCPUBenchGateBytes, func(deadline time.Time) int64 {
		return relayWaitBytes(h.mock, relayCPUBenchIterBytes, deadline)
	})
	s := SnapshotUDPRelayStats()
	pktsPerBatch := relayS2CPktsPerBatch(s)
	t.Logf("RESULT_CPU site=M3-relay-s2c-isolated goos=%s ns_per_b=%.1f max_ns_per_b=%.1f wall=%v s2c_batch_reads=%d s2c_batch_pkts=%d pkts_per_batch=%.2f min_pkts_per_batch=%.1f s2c_spins=%d",
		runtime.GOOS, nsPerB, maxNsPerB, time.Since(wallStart).Round(time.Millisecond),
		s.S2CBatchReads, s.S2CBatchPkts, pktsPerBatch, relayS2CMinPktsPerBatch, s.S2CSendSpins)
	if nsPerB > maxNsPerB {
		t.Fatalf("relay S2C CPU budget: ns_per_b=%.1f want <= %.1f", nsPerB, maxNsPerB)
	}
	if runtime.GOOS == "windows" && pktsPerBatch < relayS2CMinPktsPerBatch {
		t.Logf("OPEN: Windows loopback S2C coalesce=%.2f pkts/batch (gate uses relaxed ns/B only)", pktsPerBatch)
	}
}

func relayMaxU64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

// TestLocalizeRelayS2CHotpathStats logs batch coalesce efficiency under flood (500ms cap).
func TestLocalizeRelayS2CHotpathStats(t *testing.T) {
	const benchDur = 500 * time.Millisecond
	payload := make([]byte, 512)
	EnableRelayStatsForBench()
	ResetUDPRelayStats()

	sink, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	relayConn, err := net.DialUDP("udp", nil, sink.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer relayConn.Close()
	TuneMasqueUDPSocketBuffers(relayConn)

	mock := &relayS2CBenchSender{}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	relayAddr := relayConn.LocalAddr().(*net.UDPAddr)
	wg.Add(1)
	go func() {
		defer wg.Done()
		relayPumpS2CBenchUDP(sink, payload, relayAddr, stop)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = proxyConnReceive(context.Background(), relayConn, mock)
	}()

	time.Sleep(benchDur)
	close(stop)
	_ = relayConn.Close()
	wg.Wait()

	s := SnapshotUDPRelayStats()
	mbps := float64(mock.bytes.Load()*8) / benchDur.Seconds() / 1e6
	pktsPerBatch := float64(s.S2CBatchPkts) / float64(relayMaxU64(s.S2CBatchReads, 1))
	t.Logf("RESULT_RELAY_HOTPATH mbps=%.1f s2c_in=%d s2c_out=%d batch_reads=%d batch_pkts=%d pkts_per_batch=%.2f send_spins=%d",
		mbps, s.S2CUDPIn, s.S2CDatagramOut, s.S2CBatchReads, s.S2CBatchPkts, pktsPerBatch, s.S2CSendSpins)
	if s.S2CBatchReads > 0 && pktsPerBatch < 1.5 {
		t.Logf("OPEN: S2C batch coalesce low (%.2f pkts/batch) — loopback flood may not pre-fill RX queue", pktsPerBatch)
	}
}

// TestGATERelayS2CBatchCoalesce verifies readOnwardUDPBatch drains multiple queued datagrams per syscall round.
func TestGATERelayS2CBatchCoalesce(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	const burst = 16
	payload := make([]byte, 512)
	sink, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	relayConn, err := net.DialUDP("udp", nil, sink.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer relayConn.Close()
	TuneMasqueUDPSocketBuffers(relayConn)
	TuneMasqueUDPSocketBuffers(sink)

	relayAddr := relayConn.LocalAddr().(*net.UDPAddr)
	for range burst {
		if _, err := sink.WriteToUDP(payload, relayAddr); err != nil {
			t.Fatal(err)
		}
	}

	buf := make([]byte, RelayMaxUDPPayloadBytes()+1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	payloads, err := readOnwardUDPBatch(ctx, relayConn, buf, h3DownlinkUDPBatchWire, onwardUDPWireLenRaw)
	if err != nil && len(payloads) == 0 {
		t.Fatalf("readOnwardUDPBatch: %v", err)
	}
	if len(payloads) < relayS2CMinPktsPerBatch {
		t.Fatalf("relay S2C batch coalesce: queued=%d got=%d want>=%.0f (readOnwardUDPBatch zero-deadline drain)",
			burst, len(payloads), relayS2CMinPktsPerBatch)
	}
	t.Logf("RESULT_RELAY_COALESCE queued=%d drained=%d pkts_per_round=%d", burst, len(payloads), len(payloads))
}
