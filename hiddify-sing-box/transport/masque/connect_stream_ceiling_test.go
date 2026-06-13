package masque

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque/h3"
)

const (
	connectStreamFieldCeilingMbps       = 14.5 // VPS invoke.py BENCH_KPI_DOWN_MBIT
	connectStreamCeilingTolerancePct    = 0.35
	connectStreamParallelStreams        = 4
	connectStreamParallelSumMinMbps     = 50.0 // iperf -P4 field ~58 Mbit/s; synth guard
	connectStreamParallelPerStreamFloor = 4.0  // parallel streams share windowed credit; guard against full stall
)

func connectStreamCeilingBand() (min, max float64) {
	min = connectStreamFieldCeilingMbps * (1 - connectStreamCeilingTolerancePct)
	max = connectStreamFieldCeilingMbps * (1 + connectStreamCeilingTolerancePct)
	return min, max
}

// TestMeasureTCPDownloadWriteToMbpsContract guards prod download helper (S63).
func TestMeasureTCPDownloadWriteToMbpsContract(t *testing.T) {
	t.Parallel()

	plain, _ := net.Pipe()
	defer plain.Close()
	if _, _, err := measureTCPDownloadWriteToMbps(plain, 10*time.Millisecond); err == nil {
		t.Fatal("plain net.Conn must fail without io.WriterTo")
	}

	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()
	go func() {
		buf := make([]byte, 64*1024)
		deadline := time.Now().Add(200 * time.Millisecond)
		for time.Now().Before(deadline) {
			if _, err := srv.Write(buf); err != nil {
				return
			}
		}
	}()

	n, mbps, err := measureTCPDownloadWriteToMbps(readAsWriterTo{cli}, 80*time.Millisecond)
	if err != nil {
		t.Fatalf("WriterTo drain: %v", err)
	}
	if n < localizeBenchMinBytes {
		t.Fatalf("WriterTo bytes=%d want >= %d", n, localizeBenchMinBytes)
	}
	if mbps < connectStreamLocalizeCeilingMin {
		t.Fatalf("WriterTo mbps=%.1f too slow for sanity check", mbps)
	}
}

// downloadReadProbeConn counts Read calls during measureTCPDownloadMbps drain (S99 anti-pattern guard).
type downloadReadProbeConn struct {
	net.Conn
	readCalls atomic.Int64
}

func (c *downloadReadProbeConn) Read(p []byte) (int, error) {
	c.readCalls.Add(1)
	return c.Conn.Read(p)
}

// TestMasqueConnectStreamMeasureTCPDownloadMbpsAntiPattern (S99): connect-stream synth gates must use
// measureTCPDownloadWriteToMbps (prod writer_to), not measureTCPDownloadMbps (Read skips downloadActive).
func TestMasqueConnectStreamMeasureTCPDownloadMbpsAntiPattern(t *testing.T) {
	h := startConnectStreamDownloadHarness(t, instantBidiLink{})
	defer h.close()

	probe := &downloadReadProbeConn{Conn: h.conn}
	_, readMbps, err := measureTCPDownloadMbps(probe, localizeBenchDuration)
	if err != nil {
		t.Fatalf("Read-path download: %v", err)
	}
	if probe.readCalls.Load() == 0 {
		t.Fatal("measureTCPDownloadMbps must drain via Read (anti-pattern for CONNECT-stream KPI)")
	}

	h2 := startConnectStreamDownloadHarness(t, instantBidiLink{})
	defer h2.close()
	_, writeToMbps, err := measureTCPDownloadWriteToMbps(h2.conn, localizeBenchDuration)
	if err != nil {
		t.Fatalf("WriteTo download: %v", err)
	}
	if writeToMbps < connectStreamLocalizeFastMbps {
		t.Fatalf("WriteTo download %.1f Mbit/s (want >= %.0f prod path)", writeToMbps, connectStreamLocalizeFastMbps)
	}
	t.Logf("connect-stream download anti-pattern guard: Read=%.1f Mbit/s WriteTo=%.1f Mbit/s (KPI gates use WriteTo only)",
		readMbps, writeToMbps)
}

// TestMasqueConnectStreamReadPathSkipsDownloadActive (S104/S83): Read-path drain never toggles
// downloadActive or QUIC framer boost; WriteTo prod path does — explains false Read-path KPI confidence.
func TestMasqueConnectStreamReadPathSkipsDownloadActive(t *testing.T) {
	t.Setenv("MASQUE_H3_BIDI_DUPLEX_COORD", "1")

	var readHookActive atomic.Int32
	h3.SetTestBidiDownloadActiveHook(func(active bool) {
		if active {
			readHookActive.Add(1)
		}
	})
	t.Cleanup(func() { h3.SetTestBidiDownloadActiveHook(nil) })

	hRead := startConnectStreamDownloadHarness(t, instantBidiLink{})
	defer hRead.close()
	tcRead, ok := unwrapH3TunnelConn(hRead.conn)
	if !ok {
		t.Fatal("expected *h3.TunnelConn under Read-path harness conn")
	}
	_, readMbps, err := measureTCPDownloadMbps(hRead.conn, localizeBenchDuration)
	if err != nil {
		t.Fatalf("Read-path download: %v", err)
	}
	if tcRead.DownloadActive() {
		t.Fatal("Read-path drain must not leave downloadActive set")
	}
	if readHookActive.Load() != 0 {
		t.Fatalf("Read-path drain invoked setBidiDownloadActive %d times (want 0)", readHookActive.Load())
	}
	if readMbps <= connectStreamVPSKPITargetDownMbps {
		t.Fatalf("Read-path instant %.1f Mbit/s (want > %.0f false-positive premise)", readMbps, connectStreamVPSKPITargetDownMbps)
	}

	var writeHookActive atomic.Int32
	h3.SetTestBidiDownloadActiveHook(func(active bool) {
		if active {
			writeHookActive.Add(1)
		}
	})

	hWrite := startConnectStreamDownloadHarness(t, instantBidiLink{})
	defer hWrite.close()
	tcWrite, ok := unwrapH3TunnelConn(hWrite.conn)
	if !ok {
		t.Fatal("expected *h3.TunnelConn under WriteTo harness conn")
	}
	_, writeToInstantMbps, err := measureTCPDownloadWriteToMbps(hWrite.conn, localizeBenchDuration)
	if err != nil {
		t.Fatalf("WriteTo instant download: %v", err)
	}
	if writeHookActive.Load() == 0 {
		t.Fatal("WriteTo drain must invoke setBidiDownloadActive(true)")
	}
	if tcWrite.DownloadActive() {
		t.Fatal("downloadActive must return to zero after WriteTo drain")
	}
	if writeToInstantMbps < connectStreamLocalizeFastMbps {
		t.Fatalf("WriteTo instant %.1f Mbit/s (want >= %.0f)", writeToInstantMbps, connectStreamLocalizeFastMbps)
	}

	hWindowed := startConnectStreamDownloadHarness(t, benchWindowedBidiLink())
	defer hWindowed.close()
	_, writeToWindowedMbps, err := measureTCPDownloadWriteToMbps(hWindowed.conn, localizeBenchDuration)
	if err != nil {
		t.Fatalf("WriteTo windowed download: %v", err)
	}
	if writeToWindowedMbps < connectStreamVPSKPITargetDownMbps {
		t.Fatalf("WriteTo windowed %.1f Mbit/s (want > %.0f)", writeToWindowedMbps, connectStreamVPSKPITargetDownMbps)
	}

	deltaMbps := readMbps - writeToWindowedMbps
	const minReadWriteToDeltaMbps = 30.0
	if deltaMbps < minReadWriteToDeltaMbps {
		t.Fatalf("Read vs WriteTo windowed Δ=%.1f Mbit/s (want >= %.0f): Read skips downloadActive → false confidence",
			deltaMbps, minReadWriteToDeltaMbps)
	}
	t.Logf("connect-stream Read-path negative control: Read=%.1f WriteTo instant=%.1f WriteTo windowed=%.1f Δ=%.1f Mbit/s",
		readMbps, writeToInstantMbps, writeToWindowedMbps, deltaMbps)
}

// TestMasqueBenchCeilingDownload (K-S1): prod WriteTo + windowed bidi exceeds VPS KPI when
// MASQUE_QUIC_DOWNLOAD_EAGER_WINDOW is on (default); legacy sb-peer RTT model when off.
func TestMasqueBenchCeilingDownload(t *testing.T) {
	const duration = localizeBenchDuration
	link := benchWindowedBidiLink()
	r := benchConnectStreamDownloadLayerWriteTo(t, "L3", link, duration)
	if r.err != nil {
		t.Fatalf("L3 WriteTo download: %v", r.err)
	}
	t.Logf("connect-stream ceiling WriteTo L3: %.1f Mbit/s (%d bytes)", r.mbps, r.bytes)

	if r.mbps <= connectStreamVPSKPITargetDownMbps {
		t.Fatalf("K-S1 windowed WriteTo: %.1f Mbit/s want > %.0f", r.mbps, connectStreamVPSKPITargetDownMbps)
	}
	if r.bytes < localizeBenchMinBytes {
		t.Fatalf("bytes=%d want >= %d", r.bytes, localizeBenchMinBytes)
	}
}

// TestMasqueConnectStreamParallelStreams models iperf -P4: N independent windowed streams, SUM ≥50 Mbit/s (S5).
func TestMasqueConnectStreamParallelStreams(t *testing.T) {
	const duration = localizeBenchDuration

	pool := startConnectStreamParallelPool(t, benchWindowedBidiLink())
	defer pool.close()

	dialCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	type streamOutcome struct {
		idx   int
		mbps  float64
		bytes int64
		err   error
	}

	outcomes := make([]streamOutcome, connectStreamParallelStreams)
	var wg sync.WaitGroup
	for i := 0; i < connectStreamParallelStreams; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			time.Sleep(time.Duration(idx) * 30 * time.Millisecond)
			conn, err := pool.dial(dialCtx)
			if err != nil {
				outcomes[idx] = streamOutcome{idx: idx, err: err}
				return
			}
			defer conn.Close()
			n, mbps, err := measureTCPDownloadWriteToMbps(conn, duration)
			outcomes[idx] = streamOutcome{idx: idx, mbps: mbps, bytes: n, err: err}
		}(i)
	}
	wg.Wait()

	var sumMbps float64
	for _, o := range outcomes {
		if o.err != nil {
			t.Fatalf("stream %d: %v", o.idx, o.err)
		}
		t.Logf("stream %d: %.1f Mbit/s (%d bytes)", o.idx, o.mbps, o.bytes)
		if o.mbps < connectStreamParallelPerStreamFloor {
			t.Fatalf("stream %d: %.1f Mbit/s want >= %.0f per-stream floor", o.idx, o.mbps, connectStreamParallelPerStreamFloor)
		}
		if o.bytes < localizeBenchMinBytes/4 {
			t.Fatalf("stream %d bytes=%d want >= %d", o.idx, o.bytes, localizeBenchMinBytes/4)
		}
		sumMbps += o.mbps
	}

	t.Logf("parallel SUM: %.1f Mbit/s (%d streams, WriteTo + windowed bidi)", sumMbps, connectStreamParallelStreams)
	if sumMbps < connectStreamParallelSumMinMbps {
		t.Fatalf("parallel SUM %.1f Mbit/s want >= %.0f (per-stream ceiling × N, not shared bottleneck)",
			sumMbps, connectStreamParallelSumMinMbps)
	}
}

// TestConnectStreamDockerH3KPIInProcGuard proxies docker connect-stream-h3 KPI on prod
// windowed bidi link (tcp_down >= 21 in run_local.py @ netem 35 ms).
func TestConnectStreamDockerH3KPIInProcGuard(t *testing.T) {
	if !h3.DownloadEagerWindowEnabled() {
		t.Skip("MASQUE_QUIC_DOWNLOAD_EAGER_WINDOW=0")
	}
	const duration = localizeBenchDuration
	link := benchWindowedBidiLink()
	r := benchConnectStreamDownloadLayerWriteTo(t, "L3", link, duration)
	if r.err != nil {
		t.Fatalf("L3 WriteTo download: %v", r.err)
	}
	t.Logf("connect-stream docker H3 KPI proxy: %.1f Mbit/s (%d B)", r.mbps, r.bytes)
	if r.mbps <= connectStreamVPSKPITargetDownMbps {
		t.Fatalf("download %.1f Mbit/s want > %.0f (connect-stream download gate)",
			r.mbps, connectStreamVPSKPITargetDownMbps)
	}
}

// connectStreamFieldRemoteRTT models higher RTT on docker remote client → VPS :4438
// (BENCH_FIELD_WARMUP + real path often >35 ms netem lab).
const connectStreamFieldRemoteRTT = 70 * time.Millisecond

// connectStreamFieldRemoteRTTMax covers docker NAT + real VPS path (often 80–100 ms).
const connectStreamFieldRemoteRTTMax = 100 * time.Millisecond

func benchConnectStreamFieldRemoteRTTKPI(t *testing.T, rtt time.Duration) {
	t.Helper()
	if !h3.DownloadEagerWindowEnabled() {
		t.Skip("MASQUE_QUIC_DOWNLOAD_EAGER_WINDOW=0")
	}
	link := benchWindowedBidiLink()
	link.rtt = rtt
	r := benchConnectStreamDownloadLayerWriteTo(t, "L3", link, localizeBenchDuration)
	if r.err != nil {
		t.Fatalf("L3 WriteTo download @ RTT %v: %v", link.rtt, r.err)
	}
	t.Logf("field remote RTT guard: %.1f Mbit/s @ %v (%d B)", r.mbps, link.rtt, r.bytes)
	if r.mbps <= connectStreamVPSKPITargetDownMbps {
		t.Fatalf("download %.1f Mbit/s want > %.0f (REF1-2-field remote RTT guard @ %v)",
			r.mbps, connectStreamVPSKPITargetDownMbps, link.rtt)
	}
}

// TestConnectStreamFieldRemoteRTT70msKPI (REF1-2-field): prod eager-window path must stay
// >21 Mbit/s at 70 ms RTT — naive 64 KiB/RTT ≈ 7 Mbit/s without wake/poke parity.
func TestConnectStreamFieldRemoteRTT70msKPI(t *testing.T) {
	benchConnectStreamFieldRemoteRTTKPI(t, connectStreamFieldRemoteRTT)
}

// TestConnectStreamFieldRemoteRTT100msKPI (REF1-2-field): docker remote → VPS often exceeds
// 70 ms RTT; prod wake/poke must stay >21 Mbit/s (64 KiB/100 ms ≈ 5 Mbit/s naive ceiling).
func TestConnectStreamFieldRemoteRTT100msKPI(t *testing.T) {
	benchConnectStreamFieldRemoteRTTKPI(t, connectStreamFieldRemoteRTTMax)
}
