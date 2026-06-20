package masque_test

// GATE-H3-SYNTH: paired H2/H3 prod stack throughput gates with diagnostic FAIL messages.

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/masque"
)

func measureProdStackDownloadMbps(
	t *testing.T,
	socksPort uint16,
	targetPort uint16,
	duration time.Duration,
) (int64, float64) {
	t.Helper()
	conn := masque.ExportSocksTCPDial(t, socksPort, targetPort)
	if err := conn.SetDeadline(time.Now().Add(duration + 5*time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	n, mbps, err := masque.ExportMeasureTCPDownloadWriteToMbps(conn, duration)
	if err != nil && n == 0 {
		t.Fatalf("prod stack WriteTo: %v", err)
	}
	return n, mbps
}

func measureProdStackUploadMbps(
	t *testing.T,
	socksPort uint16,
	targetPort uint16,
	duration time.Duration,
) (int64, float64) {
	t.Helper()
	conn := masque.ExportSocksTCPDial(t, socksPort, targetPort)
	if err := conn.SetDeadline(time.Now().Add(duration + 5*time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	n, mbps, err := masque.ExportMeasureTCPUploadMbps(conn, duration)
	if err != nil && n == 0 {
		t.Fatalf("prod stack upload: %v", err)
	}
	return n, mbps
}

type prodStackDuplexSample struct {
	DownMbps     float64
	UpMbps       float64
	TransportErr error // early reset before bench bytes (n==0 on WriteTo)
}

func measureProdStackDuplexSample(conn net.Conn, duration time.Duration) prodStackDuplexSample {
	type downRes struct {
		mbps float64
		err  error
	}
	type upRes struct {
		bytes int64
	}
	downDone := make(chan downRes, 1)
	upDone := make(chan upRes, 1)
	start := make(chan struct{})
	downloadArmed := make(chan struct{}, 1)
	restoreHook := masque.ExportInstallDuplexDownloadArmedHook(downloadArmed)
	defer restoreHook()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		n, mbps, err := masque.ExportMeasureTCPDownloadWriteToMbps(conn, duration)
		if err != nil && n == 0 {
			downDone <- downRes{err: err}
			return
		}
		downDone <- downRes{mbps: mbps}
	}()
	go func() {
		defer wg.Done()
		<-start
		<-downloadArmed
		chunk := make([]byte, 256*1024)
		var upTotal int64
		stop := time.Now().Add(duration)
		for time.Now().Before(stop) {
			n, err := conn.Write(chunk)
			if n > 0 {
				upTotal += int64(n)
			}
			if err != nil {
				break
			}
		}
		upDone <- upRes{bytes: upTotal}
	}()
	close(start)
	dr := <-downDone
	ur := <-upDone
	wg.Wait()
	secs := duration.Seconds()
	if secs <= 0 {
		secs = 1
	}
	upMbps := float64(ur.bytes*8) / secs / 1e6
	if dr.err != nil {
		return prodStackDuplexSample{UpMbps: upMbps, TransportErr: dr.err}
	}
	return prodStackDuplexSample{DownMbps: dr.mbps, UpMbps: upMbps}
}

func measureProdStackDuplexMbps(t *testing.T, conn net.Conn, duration time.Duration) (downMbps, upMbps float64) {
	t.Helper()
	sample := measureProdStackDuplexSample(conn, duration)
	if sample.TransportErr != nil {
		t.Fatalf("concurrent WriteTo download: %v", sample.TransportErr)
	}
	return sample.DownMbps, sample.UpMbps
}

func duplexSamplePass(down, up, threshold, maxRatio float64) bool {
	minLeg := down
	if up < minLeg {
		minLeg = up
	}
	maxLeg := down
	if up > maxLeg {
		maxLeg = up
	}
	ratio := 1.0
	if minLeg > 0 {
		ratio = maxLeg / minLeg
	}
	return down >= threshold && up >= threshold && minLeg > 0 && ratio <= maxRatio
}

func measureProdStackDownloadReadMbps(
	t *testing.T,
	socksPort uint16,
	targetPort uint16,
	duration time.Duration,
) (int64, float64) {
	t.Helper()
	conn := masque.ExportSocksTCPDial(t, socksPort, targetPort)
	if err := conn.SetDeadline(time.Now().Add(duration + 5*time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	buf := make([]byte, 256*1024)
	var total int64
	stop := time.Now().Add(duration)
	for time.Now().Before(stop) {
		n, err := conn.Read(buf)
		if n > 0 {
			total += int64(n)
		}
		if err != nil {
			break
		}
	}
	secs := duration.Seconds()
	if secs <= 0 {
		secs = 1
	}
	return total, float64(total*8) / secs / 1e6
}

func measureProdStackDownloadReadMbpsWindowed(
	t *testing.T,
	socksPort uint16,
	targetPort uint16,
	duration time.Duration,
) (int64, float64) {
	t.Helper()
	conn := masque.ExportSocksTCPDial(t, socksPort, targetPort)
	conn = masque.ExportWrapBenchWindowedBidiLinkH3Prod(conn)
	if err := conn.SetDeadline(time.Now().Add(duration + 5*time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	buf := make([]byte, 256*1024)
	var total int64
	stop := time.Now().Add(duration)
	for time.Now().Before(stop) {
		n, err := conn.Read(buf)
		if n > 0 {
			total += int64(n)
		}
		if err != nil {
			break
		}
	}
	secs := duration.Seconds()
	if secs <= 0 {
		secs = 1
	}
	return total, float64(total*8) / secs / 1e6
}

func measureProdStackUploadMbpsWindowed(
	t *testing.T,
	socksPort uint16,
	targetPort uint16,
	duration time.Duration,
) (int64, float64) {
	t.Helper()
	conn := masque.ExportSocksTCPDial(t, socksPort, targetPort)
	conn = masque.ExportWrapBenchWindowedBidiLinkH3Prod(conn)
	if err := conn.SetDeadline(time.Now().Add(duration + 5*time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	n, mbps, err := masque.ExportMeasureTCPUploadMbps(conn, duration)
	if err != nil && n == 0 {
		t.Fatalf("prod stack upload windowed: %v", err)
	}
	return n, mbps
}

func assertSynthProdMbps(t *testing.T, layer, leg string, mbps float64, hint string) {
	t.Helper()
	want := masque.ExportConnectStreamSynthProdMinMbps
	if mbps < want {
		t.Fatalf("%s", masque.ExportSynthKPIDiagnostic(layer, leg, mbps, want, hint))
	}
}

// TestGATEH2SynthProdStackDownloadAnchor (H2 regression) — H2 prod stack download must stay >= 200 Mbit/s.
func TestGATEH2SynthProdStackDownloadAnchor(t *testing.T) {
	dur := masque.ExportConnectStreamSynthProdBenchDuration
	targetPort := masque.ExportStartH2ProdStackBulkDownloadTarget(t)
	proxyPort := startLaunchMasqueStackH2ConnectStreamServer(t)
	socksPort := masque.ExportStartH2ConnectStreamSocksRouter(t, proxyPort)

	n, mbps := measureProdStackDownloadMbps(t, socksPort, targetPort, dur)
	t.Logf("GATE-H2-SYNTH download: %.1f Mbit/s (%d bytes)", mbps, n)
	assertSynthProdMbps(t, "[H2-L0 prod stack]", "tcp_down WriteTo", mbps,
		"LaunchMasqueStack H2 + SOCKS/CM; anchor for H3 parity")
}

// TestGATEH2SynthProdStackUploadAnchor (H2 regression) — H2 prod stack upload must stay >= 200 Mbit/s.
func TestGATEH2SynthProdStackUploadAnchor(t *testing.T) {
	dur := masque.ExportConnectStreamSynthProdBenchDuration
	targetPort := masque.ExportStartH2ConnectStreamUploadTarget(t)
	proxyPort := startLaunchMasqueStackH2ConnectStreamServer(t)
	socksPort := masque.ExportStartH2ConnectStreamSocksRouter(t, proxyPort)

	n, mbps := measureProdStackUploadMbps(t, socksPort, targetPort, dur)
	t.Logf("GATE-H2-SYNTH upload: %.1f Mbit/s (%d bytes)", mbps, n)
	assertSynthProdMbps(t, "[H2-L0 prod stack]", "tcp_up ReadFrom/Write", mbps,
		"LaunchMasqueStack H2 + SOCKS/CM upload leg")
}

// TestGATEH3SynthProdStackDownload (GATE-H3-SYNTH) — H3 prod stack download >= 200 Mbit/s.
func TestGATEH3SynthProdStackDownload(t *testing.T) {
	dur := masque.ExportConnectStreamSynthProdBenchDuration
	targetPort := masque.ExportStartH2ProdStackBulkDownloadTarget(t)
	proxyPort := startLaunchMasqueStackH3ConnectStreamServer(t)
	socksPort := masque.ExportStartH3ConnectStreamSocksRouter(t, proxyPort)

	n, mbps := measureProdStackDownloadMbps(t, socksPort, targetPort, dur)
	t.Logf("GATE-H3-SYNTH download: %.1f Mbit/s (%d bytes)", mbps, n)
	assertSynthProdMbps(t, "[H3-L0 prod stack]", "tcp_down WriteTo", mbps,
		"LaunchMasqueStack H3 + SOCKS/CM; hot path client/relay/quic")
}

// TestGATEH3SynthProdStackUpload (GATE-H3-SYNTH) — H3 prod stack upload >= 200 Mbit/s.
func TestGATEH3SynthProdStackUpload(t *testing.T) {
	dur := masque.ExportConnectStreamSynthProdBenchDuration
	targetPort := masque.ExportStartH2ConnectStreamUploadTarget(t)
	proxyPort := startLaunchMasqueStackH3ConnectStreamServer(t)
	socksPort := masque.ExportStartH3ConnectStreamSocksRouter(t, proxyPort)

	n, mbps := measureProdStackUploadMbps(t, socksPort, targetPort, dur)
	t.Logf("GATE-H3-SYNTH upload: %.1f Mbit/s (%d bytes)", mbps, n)
	assertSynthProdMbps(t, "[H3-L0 prod stack]", "tcp_up Write", mbps,
		"LaunchMasqueStack H3 + SOCKS/CM upload leg")
}

// TestGATEH3SynthPairedProdStackDownload (GATE-H3-SYNTH) — H3 download within 85% of H2 on same harness.
func TestGATEH3SynthPairedProdStackDownload(t *testing.T) {
	dur := masque.ExportConnectStreamSynthProdBenchDuration
	targetPort := masque.ExportStartH2ProdStackBulkDownloadTarget(t)

	h2Proxy := startLaunchMasqueStackH2ConnectStreamServer(t)
	h2Socks := masque.ExportStartH2ConnectStreamSocksRouter(t, h2Proxy)
	_, h2Mbps := measureProdStackDownloadMbps(t, h2Socks, targetPort, dur)

	h3Proxy := startLaunchMasqueStackH3ConnectStreamServer(t)
	h3Socks := masque.ExportStartH3ConnectStreamSocksRouter(t, h3Proxy)
	_, h3Mbps := measureProdStackDownloadMbps(t, h3Socks, targetPort, dur)

	t.Logf("GATE-H3-SYNTH paired download: H2=%.1f H3=%.1f Mbit/s ratio=%.2f",
		h2Mbps, h3Mbps, h3Mbps/h2Mbps)

	assertSynthProdMbps(t, "[H2-L0 prod stack]", "tcp_down anchor", h2Mbps, "H2 regression anchor")
	assertSynthProdMbps(t, "[H3-L0 prod stack]", "tcp_down WriteTo", h3Mbps,
		"paired with H2 on bulk download target")

	minH3 := h2Mbps * masque.ExportConnectStreamSynthParityMinRatio
	if h3Mbps < minH3 {
		t.Fatalf("[H3-L0 vs H2-L0] H3/H2 download ratio: H3=%.1f H2=%.1f (%.2f) want >= %.2f (H3 >= %.1f Mbit/s); localize client/relay/quic hot path",
			h3Mbps, h2Mbps, h3Mbps/h2Mbps, masque.ExportConnectStreamSynthParityMinRatio, minH3)
	}
}

// TestGATEH3SynthBidiDuplexProdStack (GATE-H3-SYNTH) — concurrent upload + WriteTo download on H3 prod stack.
// One masque stack + N dials (prod parity). Do not use go test -count to repeat stack lifecycle.
func TestGATEH3SynthBidiDuplexProdStack(t *testing.T) {
	dur := masque.ExportConnectStreamSynthProdBenchDuration
	samples := int(masque.ExportConnectStreamSynthDuplexGateSamples)
	minPass := int(masque.ExportConnectStreamSynthDuplexGateMinPass)
	threshold := masque.ExportConnectStreamSynthProdMinMbps
	maxRatio := masque.ExportConnectStreamSynthDuplexMaxRatio

	targetPort := masque.ExportStartH2ProdStackBulkDownloadTarget(t)
	proxyPort := startLaunchMasqueStackH3ConnectStreamServer(t)
	socksPort := masque.ExportStartH3ConnectStreamSocksRouter(t, proxyPort)

	var pass, transportErr int
	var bestMin float64
	for i := 0; i < samples; i++ {
		conn := masque.ExportSocksTCPDial(t, socksPort, targetPort)
		if err := conn.SetDeadline(time.Now().Add(dur + 8*time.Second)); err != nil {
			t.Fatalf("set deadline: %v", err)
		}
		sample := measureProdStackDuplexSample(conn, dur)
		_ = conn.Close()
		if sample.TransportErr != nil {
			transportErr++
			t.Logf("GATE-H3-SYNTH duplex sample %d/%d: transport reset: %v", i+1, samples, sample.TransportErr)
			continue
		}
		minLeg := sample.DownMbps
		if sample.UpMbps < minLeg {
			minLeg = sample.UpMbps
		}
		maxLeg := sample.DownMbps
		if sample.UpMbps > maxLeg {
			maxLeg = sample.UpMbps
		}
		ratio := maxLeg / minLeg
		if minLeg <= 0 {
			ratio = 0
		}
		ok := duplexSamplePass(sample.DownMbps, sample.UpMbps, threshold, maxRatio)
		if ok {
			pass++
		}
		if minLeg > bestMin {
			bestMin = minLeg
		}
		t.Logf("GATE-H3-SYNTH duplex sample %d/%d: down=%.1f up=%.1f min=%.1f ratio=%.2f pass=%v",
			i+1, samples, sample.DownMbps, sample.UpMbps, minLeg, ratio, ok)
	}
	t.Logf("GATE-H3-SYNTH duplex summary: pass=%d/%d transport_err=%d best_min=%.1f (need pass>=%d)",
		pass, samples, transportErr, bestMin, minPass)

	if transportErr > 0 {
		t.Fatalf("GATE-H3-SYNTH duplex: %d/%d transport reset on single-stack dials — localize teardown/harness, not FC",
			transportErr, samples)
	}
	if pass < minPass {
		t.Fatalf("GATE-H3-SYNTH duplex: pass=%d/%d (need >=%d @%.0f Mbit/s each leg, ratio<=%.0f); best_min=%.1f",
			pass, samples, minPass, threshold, maxRatio, bestMin)
	}
}

// TestLocalizeConnectStreamH3Symmetric1G logs separate-leg throughput vs 1 Gbit/s symmetric target (OPEN).
func TestLocalizeConnectStreamH3Symmetric1G(t *testing.T) {
	const targetMbps = 1000.0
	const maxAsym = 1.25
	dur := masque.ExportConnectStreamSynthProdBenchDuration
	downPort := masque.ExportStartH2ProdStackBulkDownloadTarget(t)
	upPort := masque.ExportStartH2ConnectStreamUploadTarget(t)
	proxyPort := startLaunchMasqueStackH3ConnectStreamServer(t)
	socksPort := masque.ExportStartH3ConnectStreamSocksRouter(t, proxyPort)

	_, downMbps := measureProdStackDownloadMbps(t, socksPort, downPort, dur)
	_, upMbps := measureProdStackUploadMbps(t, socksPort, upPort, dur)
	asym := downMbps / upMbps
	if upMbps > downMbps {
		asym = upMbps / downMbps
	}
	t.Logf("connect-stream-h3 symmetric-1G localize: down=%.1f up=%.1f asym=%.2f target=%.0f",
		downMbps, upMbps, asym, targetMbps)
	if downMbps < targetMbps || upMbps < targetMbps {
		t.Logf("OPEN: separate legs below %.0f Mbit/s target", targetMbps)
	}
	if asym > maxAsym {
		t.Logf("OPEN: leg asymmetry %.2f > %.2f", asym, maxAsym)
	}
}

// TestLocalizeConnectStreamH3DuplexSymmetric1G samples saturated duplex vs 1 Gbit/s symmetric target (OPEN).
func TestLocalizeConnectStreamH3DuplexSymmetric1G(t *testing.T) {
	const samples = 8
	const targetMbps = 1000.0
	const maxRatio = 1.25
	dur := masque.ExportConnectStreamSynthProdBenchDuration
	targetPort := masque.ExportStartH2ProdStackBulkDownloadTarget(t)
	proxyPort := startLaunchMasqueStackH3ConnectStreamServer(t)
	socksPort := masque.ExportStartH3ConnectStreamSocksRouter(t, proxyPort)

	var pass, minOfMin float64
	for i := 0; i < samples; i++ {
		conn := masque.ExportSocksTCPDial(t, socksPort, targetPort)
		_ = conn.SetDeadline(time.Now().Add(dur + 8*time.Second))
		down, up := measureProdStackDuplexMbps(t, conn, dur)
		minLeg := down
		if up < minLeg {
			minLeg = up
		}
		maxLeg := down
		if up > maxLeg {
			maxLeg = up
		}
		ratio := 1.0
		if minLeg > 0 {
			ratio = maxLeg / minLeg
		}
		ok := minLeg >= targetMbps && ratio <= maxRatio
		if ok {
			pass++
		}
		if i == 0 || minLeg < minOfMin || minOfMin == 0 {
			minOfMin = minLeg
		}
		t.Logf("duplex-1G sample %d/%d: down=%.1f up=%.1f min=%.1f ratio=%.2f pass=%v",
			i+1, samples, down, up, minLeg, ratio, ok)
		_ = conn.Close()
	}
	t.Logf("duplex-1G summary: pass=%.0f/%d min_of_min=%.1f target=%.0f ratio<=%.2f (OPEN)",
		pass, samples, minOfMin, targetMbps, maxRatio)
}

// TestLocalizeConnectStreamH3DuplexFairness samples saturated duplex KPI (localization only, no FAIL).
func TestLocalizeConnectStreamH3DuplexFairness(t *testing.T) {
	const samples = 5
	dur := masque.ExportConnectStreamSynthProdBenchDuration
	targetPort := masque.ExportStartH2ProdStackBulkDownloadTarget(t)
	proxyPort := startLaunchMasqueStackH3ConnectStreamServer(t)
	socksPort := masque.ExportStartH3ConnectStreamSocksRouter(t, proxyPort)

	var minOfMin, sumRatio float64
	for i := 0; i < samples; i++ {
		conn := masque.ExportSocksTCPDial(t, socksPort, targetPort)
		_ = conn.SetDeadline(time.Now().Add(dur + 8*time.Second))
		down, up := measureProdStackDuplexMbps(t, conn, dur)
		minLeg := down
		if up < minLeg {
			minLeg = up
		}
		maxLeg := down
		if up > maxLeg {
			maxLeg = up
		}
		ratio := 1.0
		if minLeg > 0 {
			ratio = maxLeg / minLeg
		}
		t.Logf("duplex sample %d/%d: down=%.1f up=%.1f min=%.1f ratio=%.2f",
			i+1, samples, down, up, minLeg, ratio)
		if i == 0 || minLeg < minOfMin {
			minOfMin = minLeg
		}
		sumRatio += ratio
		_ = conn.Close()
	}
	t.Logf("duplex fairness summary: min_of_min=%.1f avg_ratio=%.2f (OPEN until stable >=1000 min leg)",
		minOfMin, sumRatio/float64(samples))
}

// TestLocalizeH3DuplexStackRecycle localizes harness bug: fresh stack per subtest (go test -count
// pattern) vs one stack + multi-dial. Control must have zero transport resets; recycle may flake on Windows.
func TestLocalizeH3DuplexStackRecycle(t *testing.T) {
	const samples = 5
	dur := masque.ExportConnectStreamSynthProdBenchDuration

	t.Run("single_stack_multi_dial", func(t *testing.T) {
		targetPort := masque.ExportStartH2ProdStackBulkDownloadTarget(t)
		proxyPort := startLaunchMasqueStackH3ConnectStreamServer(t)
		socksPort := masque.ExportStartH3ConnectStreamSocksRouter(t, proxyPort)
		for i := 0; i < samples; i++ {
			conn := masque.ExportSocksTCPDial(t, socksPort, targetPort)
			_ = conn.SetDeadline(time.Now().Add(dur + 8*time.Second))
			sample := measureProdStackDuplexSample(conn, dur)
			_ = conn.Close()
			if sample.TransportErr != nil {
				t.Fatalf("sample %d/%d transport reset: %v", i+1, samples, sample.TransportErr)
			}
		}
	})

	var recycleFail int
	for i := 0; i < samples; i++ {
		i := i
		ok := t.Run(fmt.Sprintf("fresh_stack_%d", i), func(t *testing.T) {
			targetPort := masque.ExportStartH2ProdStackBulkDownloadTarget(t)
			proxyPort := startLaunchMasqueStackH3ConnectStreamServer(t)
			socksPort := masque.ExportStartH3ConnectStreamSocksRouter(t, proxyPort)
			conn := masque.ExportSocksTCPDial(t, socksPort, targetPort)
			_ = conn.SetDeadline(time.Now().Add(dur + 8*time.Second))
			sample := measureProdStackDuplexSample(conn, dur)
			_ = conn.Close()
			if sample.TransportErr != nil {
				t.Fatalf("transport reset: %v", sample.TransportErr)
			}
		})
		if !ok {
			recycleFail++
		}
	}
	if recycleFail > 0 {
		t.Logf("OPEN: fresh-stack subtests failed %d/%d — GATE must use single_stack_multi_dial, not go test -count",
			recycleFail, samples)
	}
}

// TestLocalizeH3DuplexPolarization buckets bimodal duplex poles (localization only, no FAIL).
func TestLocalizeH3DuplexPolarization(t *testing.T) {
	const samples = 20
	dur := masque.ExportConnectStreamSynthProdBenchDuration
	threshold := masque.ExportConnectStreamSynthProdMinMbps
	maxRatio := masque.ExportConnectStreamSynthDuplexMaxRatio
	targetPort := masque.ExportStartH2ProdStackBulkDownloadTarget(t)
	proxyPort := startLaunchMasqueStackH3ConnectStreamServer(t)
	socksPort := masque.ExportStartH3ConnectStreamSocksRouter(t, proxyPort)

	var poleLow, poleMid, poleHigh, pass int
	var bestMin float64
	for i := 0; i < samples; i++ {
		conn := masque.ExportSocksTCPDial(t, socksPort, targetPort)
		_ = conn.SetDeadline(time.Now().Add(dur + 8*time.Second))
		down, up := measureProdStackDuplexMbps(t, conn, dur)
		minLeg := down
		if up < minLeg {
			minLeg = up
		}
		maxLeg := down
		if up > maxLeg {
			maxLeg = up
		}
		ratio := 1.0
		if minLeg > 0 {
			ratio = maxLeg / minLeg
		}
		t.Logf("polarization %d/%d: down=%.1f up=%.1f min=%.1f ratio=%.2f",
			i+1, samples, down, up, minLeg, ratio)
		switch {
		case minLeg < 150:
			poleLow++
		case minLeg < 700:
			poleMid++
		default:
			poleHigh++
		}
		if down >= threshold && up >= threshold && minLeg > 0 && ratio <= maxRatio {
			pass++
		}
		if minLeg > bestMin {
			bestMin = minLeg
		}
		_ = conn.Close()
	}
	t.Logf("polarization summary: low<150=%d mid=[150,700)=%d high>=700=%d pass=%d/%d best_min=%.1f",
		poleLow, poleMid, poleHigh, pass, samples, bestMin)
}

func TestGATEH2SynthBidiDuplexProdStack(t *testing.T) {
	dur := masque.ExportConnectStreamSynthProdBenchDuration
	targetPort := masque.ExportStartH2ProdStackBulkDownloadTarget(t)
	proxyPort := startLaunchMasqueStackH2ConnectStreamServer(t)
	socksPort := masque.ExportStartH2ConnectStreamSocksRouter(t, proxyPort)

	conn := masque.ExportSocksTCPDial(t, socksPort, targetPort)
	if err := conn.SetDeadline(time.Now().Add(dur + 8*time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	downMbps, upMbps := measureProdStackDuplexMbps(t, conn, dur)
	t.Logf("GATE-H2-SYNTH duplex: down=%.1f up=%.1f Mbit/s", downMbps, upMbps)

	assertSynthProdMbps(t, "[H2-L1a/L2 prod stack]", "tcp_down WriteTo duplex", downMbps, "H2 bidi anchor")
	assertSynthProdMbps(t, "[H2-L1a/L2 prod stack]", "tcp_up duplex", upMbps, "H2 bidi anchor")
}

// TestLocalizeDockerH30msSequentialLegs mirrors docker run_local connect-stream-h3 @0ms:
// download-first (iperf -R Read) then fresh SOCKS upload — финальный Docker KPI ≥1000.
func TestLocalizeDockerH30msSequentialLegs(t *testing.T) {
	const maxRatio = 2.5
	dur := masque.ExportConnectStreamSynthProdBenchDuration
	targetDown := masque.ExportStartH2ProdStackBulkDownloadTarget(t)
	targetUp := masque.ExportStartH2ConnectStreamUploadTarget(t)
	proxyPort := startLaunchMasqueStackH3ConnectStreamServer(t)
	socksPort := masque.ExportStartH3ConnectStreamSocksRouter(t, proxyPort)

	_, downMbps := measureProdStackDownloadReadMbps(t, socksPort, targetDown, dur)
	t.Logf("docker-analog @0ms download-first (Read/-R): %.1f Mbit/s", downMbps)

	upSocks := masque.ExportStartH3ConnectStreamSocksRouter(t, proxyPort)
	_, upMbps := measureProdStackUploadMbps(t, upSocks, targetUp, dur)
	t.Logf("docker-analog @0ms upload leg: %.1f Mbit/s", upMbps)

	assertSynthProdMbps(t, "[H3 docker @0ms seq]", "tcp_down Read/-R", downMbps, "run_local leg1 topology")
	assertSynthProdMbps(t, "[H3 docker @0ms seq]", "tcp_up leg2", upMbps, "run_local leg2 topology")
	capUp := maxRatio * max(downMbps, 21.0)
	if upMbps > capUp {
		t.Fatalf("tcp_up %.1f > %.1f (docker @0ms asymmetry band)", upMbps, capUp)
	}
}

// TestLocalizeDockerH335msSequentialLegs mirrors docker run_local @35ms netem + sequential iperf legs.
// FAIL пока synth не воспроизводит perf-lab floor; DoD 1000+ — только Docker @0ms.
func TestLocalizeDockerH335msSequentialLegs(t *testing.T) {
	dur := masque.ExportConnectStreamSynthProdBenchDuration
	targetDown := masque.ExportStartH2ProdStackBulkDownloadTarget(t)
	targetUp := masque.ExportStartH2ConnectStreamUploadTarget(t)
	proxyPort := startLaunchMasqueStackH3ConnectStreamServer(t)
	socksPort := masque.ExportStartH3ConnectStreamSocksRouter(t, proxyPort)

	_, downMbps := measureProdStackDownloadReadMbpsWindowed(t, socksPort, targetDown, dur)
	t.Logf("docker-analog @35ms download-first: %.1f Mbit/s", downMbps)

	upSocks := masque.ExportStartH3ConnectStreamSocksRouter(t, proxyPort)
	_, upMbps := measureProdStackUploadMbpsWindowed(t, upSocks, targetUp, dur)
	t.Logf("docker-analog @35ms upload leg: %.1f Mbit/s", upMbps)

	masque.ExportAssertLocalizeDocker35msSequentialLeg(t, "tcp_down", downMbps, masque.ExportConnectStreamDocker35msSeqDownFloorMbps)
	masque.ExportAssertLocalizeDocker35msSequentialLeg(t, "tcp_up", upMbps, masque.ExportConnectStreamDocker35msSeqUpFloorMbps)
	capUp := masque.ExportConnectStreamDocker35msSeqMaxRatio * max(downMbps, 21.0)
	if upMbps > capUp {
		t.Fatalf("tcp_up %.1f > %.1f (docker @35ms asymmetry band)", upMbps, capUp)
	}
}

// TestGATEH3IPerfAnalogDownloadRead uses conn.Read (iperf -R / SOCKS relay) not WriteTo.
func TestGATEH3IPerfAnalogDownloadRead(t *testing.T) {
	dur := masque.ExportConnectStreamSynthProdBenchDuration
	targetPort := masque.ExportStartH2ProdStackBulkDownloadTarget(t)
	proxyPort := startLaunchMasqueStackH3ConnectStreamServer(t)
	socksPort := masque.ExportStartH3ConnectStreamSocksRouter(t, proxyPort)

	n, mbps := measureProdStackDownloadReadMbps(t, socksPort, targetPort, dur)
	t.Logf("iperf-analog Read download: %.1f Mbit/s (%d bytes)", mbps, n)
	assertSynthProdMbps(t, "[H3 iperf -R Read]", "tcp_down Read", mbps, "docker iperf -R analog")
}
