package masque_test

// GATE-H3-SYNTH: paired H2/H3 prod stack throughput gates with diagnostic FAIL messages.

import (
	"net"
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

func measureProdStackDuplexMbps(t *testing.T, conn net.Conn, duration time.Duration) (downMbps, upMbps float64) {
	t.Helper()
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
	go func() {
		<-start
		n, mbps, err := masque.ExportMeasureTCPDownloadWriteToMbps(conn, duration)
		if err != nil && n == 0 {
			downDone <- downRes{err: err}
			return
		}
		downDone <- downRes{mbps: mbps}
	}()
	go func() {
		<-start
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
	if dr.err != nil {
		t.Fatalf("concurrent WriteTo download: %v", dr.err)
	}
	ur := <-upDone
	secs := duration.Seconds()
	if secs <= 0 {
		secs = 1
	}
	upMbps = float64(ur.bytes*8) / secs / 1e6
	return dr.mbps, upMbps
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
func TestGATEH3SynthBidiDuplexProdStack(t *testing.T) {
	dur := masque.ExportConnectStreamSynthProdBenchDuration
	targetPort := masque.ExportStartH2ProdStackBulkDownloadTarget(t)
	proxyPort := startLaunchMasqueStackH3ConnectStreamServer(t)
	socksPort := masque.ExportStartH3ConnectStreamSocksRouter(t, proxyPort)

	conn := masque.ExportSocksTCPDial(t, socksPort, targetPort)
	if err := conn.SetDeadline(time.Now().Add(dur + 8*time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	downMbps, upMbps := measureProdStackDuplexMbps(t, conn, dur)
	minLeg := downMbps
	if upMbps < minLeg {
		minLeg = upMbps
	}
	maxLeg := downMbps
	if upMbps > maxLeg {
		maxLeg = upMbps
	}
	ratio := maxLeg / minLeg
	if minLeg <= 0 {
		ratio = 0
	}

	t.Logf("GATE-H3-SYNTH duplex: down=%.1f up=%.1f min=%.1f ratio=%.2f",
		downMbps, upMbps, minLeg, ratio)

	if downMbps < masque.ExportConnectStreamSynthProdMinMbps {
		t.Fatalf("%s", masque.ExportSynthKPIDiagnostic("[H3-L1b/L1c bidi prod stack]", "tcp_down WriteTo",
			downMbps, masque.ExportConnectStreamSynthProdMinMbps,
			"concurrent upload active — check bidi FC / wake / scheduler"))
	}
	if upMbps < masque.ExportConnectStreamSynthProdMinMbps {
		t.Fatalf("%s", masque.ExportSynthKPIDiagnostic("[H3-L1b/L1c bidi prod stack]", "tcp_up during WriteTo",
			upMbps, masque.ExportConnectStreamSynthProdMinMbps,
			"upload starved while download drains — check interleave poke"))
	}
	if minLeg > 0 && ratio > masque.ExportConnectStreamSynthDuplexMaxRatio {
		t.Fatalf("[H3-L1b/L1c bidi prod stack] asymmetry: down=%.1f up=%.1f ratio=%.2f (want <= %.0f)",
			downMbps, upMbps, ratio, masque.ExportConnectStreamSynthDuplexMaxRatio)
	}
}

// TestGATEH2SynthBidiDuplexProdStack (H2 regression) — H2 prod stack concurrent duplex >= 200 both legs.
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
