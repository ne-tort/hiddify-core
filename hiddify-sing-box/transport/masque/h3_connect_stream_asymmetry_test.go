package masque

// H3-T6-09 / GATE-H3-SYNTH: bidi duplex on prod stack (no artificial window wrap).

import (
	"net"
	"testing"
	"time"
)

const h3AsymmetryGateDuration = 12 * time.Second

func measureH3ConcurrentDuplexMbps(t *testing.T, conn net.Conn, duration time.Duration) (downMbps, upMbps float64) {
	t.Helper()
	type downRes struct {
		mbps float64
		err  error
	}
	downDone := make(chan downRes, 1)
	go func() {
		n, mbps, err := measureTCPDownloadWriteToMbps(conn, duration)
		if err != nil && n == 0 {
			downDone <- downRes{err: err}
			return
		}
		downDone <- downRes{mbps: mbps}
	}()

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
	dr := <-downDone
	if dr.err != nil {
		t.Fatalf("concurrent WriteTo download: %v", dr.err)
	}
	secs := duration.Seconds()
	if secs <= 0 {
		secs = 1
	}
	upMbps = float64(upTotal*8) / secs / 1e6
	return dr.mbps, upMbps
}

// TestH3ConnectStreamWireFCL256DuplexBand documents strict L256 wire-FC ceiling (~60 Mbit/s @ 35 ms).
// Not GATE-H3-SYNTH — use TestGATEH3SynthBidiDuplexProdStack for prod 200+ target.
func TestH3ConnectStreamWireFCL256DuplexBand(t *testing.T) {
	h := startConnectStreamDownloadHarness(t, benchWindowedBidiLinkStrictH3L256())
	defer h.close()
	if err := h.conn.SetDeadline(time.Now().Add(h3AsymmetryGateDuration + 8*time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	downMbps, upMbps := measureH3ConcurrentDuplexMbps(t, h.conn, h3AsymmetryGateDuration)
	t.Logf("H3 wire-FC L256 duplex band: down=%.1f up=%.1f Mbit/s (ceiling ~60, not prod 200+ target)",
		downMbps, upMbps)

	const wireCeilingMbps = 60.0
	if downMbps > wireCeilingMbps*1.15 {
		t.Fatalf("[H3-L1c wire harness] down=%.1f unexpected above L256 ceiling band ~%.0f (harness drift?)",
			downMbps, wireCeilingMbps)
	}
	if downMbps < connectStreamVPSKPITargetDownMbps {
		t.Fatalf("%s", synthKPIDiagnostic("[H3-L1c wire L256]", "tcp_down WriteTo", downMbps,
			connectStreamVPSKPITargetDownMbps, "weak regression floor only"))
	}
}

// TestH3ConnectStreamBidiAsymmetryRatio (GATE-H3-SYNTH wire) — strict L256 must FAIL 200+ target
// with diagnostic pointing at wire-FC ceiling vs prod stack (TestGATEH3SynthBidiDuplexProdStack).
func TestH3ConnectStreamBidiAsymmetryRatio(t *testing.T) {
	h := startConnectStreamDownloadHarness(t, benchWindowedBidiLinkStrictH3L256())
	defer h.close()
	if err := h.conn.SetDeadline(time.Now().Add(h3AsymmetryGateDuration + 8*time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	downMbps, upMbps := measureH3ConcurrentDuplexMbps(t, h.conn, h3AsymmetryGateDuration)
	minLeg := downMbps
	if upMbps < minLeg {
		minLeg = upMbps
	}
	t.Logf("H3 bidi strict L256: down=%.1f up=%.1f min=%.1f Mbit/s", downMbps, upMbps, minLeg)

	if minLeg >= connectStreamSynthProdMinMbps {
		t.Fatalf("unexpected PASS @ %.0f Mbit/s on strict L256 harness — use prod stack gate instead",
			connectStreamSynthProdMinMbps)
	}
	if downMbps < connectStreamSynthProdMinMbps {
		t.Fatalf("%s", synthKPIDiagnostic("[H3-L1c wire L256]", "tcp_down WriteTo", downMbps,
			connectStreamSynthProdMinMbps,
			"strict bidi FC ~60 Mbit/s ceiling — not prod path; fix via TestGATEH3SynthBidiDuplexProdStack"))
	}
}
