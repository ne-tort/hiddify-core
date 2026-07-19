package masque

// Shared localize bench types/thresholds (W-STR-4 PR6).

import "testing"

const (
	connectStreamLocalizeFastMbps             = 80.0
	connectStreamLocalizeUploadWindowedMin    = 4.0
	connectStreamLocalizeUploadWindowedMax    = 28.0
	connectStreamLocalizeDownloadKPIMin       = 21.0
	connectStreamLocalizeWideUploadMinMbps    = 40.0
	connectStreamLocalizeInstantUploadMinMbps = 40.0
	connectStreamLocalizeCeilingMin           = connectStreamLocalizeUploadWindowedMin
	connectStreamLocalizeCeilingMax           = connectStreamLocalizeUploadWindowedMax
)

func connectStreamCeilingBand() (min, max float64) {
	const tolerance = 0.40
	min = connectStreamVPSKPITargetDownMbps * (1 - tolerance)
	max = connectStreamVPSKPITargetDownMbps * (1 + tolerance)
	return min, max
}

type connectStreamBenchResult struct {
	layer string
	mbps  float64
	bytes int64
	err   error
}

func (r connectStreamBenchResult) ok() bool { return r.err == nil }

func assertConnectStreamWindowedCeilingBand(t *testing.T, mbps float64, context string) {
	t.Helper()
	if mbps <= connectStreamVPSKPITargetDownMbps {
		t.Fatalf("%s: %.1f Mbit/s (want > %.0f)", context, mbps, connectStreamVPSKPITargetDownMbps)
	}
}

func verdictConnectStreamDownload(l0, l1, l3 connectStreamBenchResult) string {
	switch {
	case !l0.ok() || !l1.ok() || !l3.ok():
		return "FAIL: bench error"
	case l1.mbps >= connectStreamLocalizeFastMbps && l3.mbps >= connectStreamLocalizeUploadWindowedMin && l3.mbps <= connectStreamLocalizeUploadWindowedMax:
		return "masque connect-stream bidi: L1 fast download, L3 windowed ~64KiB/RTT band → stream credit/RTT on one bidi HTTP/3 leg (not buffer size)"
	case l1.mbps < connectStreamLocalizeFastMbps && l0.mbps >= connectStreamLocalizeFastMbps:
		return "masque connect-stream: L0 fast, L1 download slow → tunnel relay or streamConn path (not wire RTT)"
	case l1.mbps >= connectStreamLocalizeFastMbps && l3.mbps > connectStreamLocalizeUploadWindowedMax:
		return "L3 window model did not reproduce download ceiling (harness calibration)"
	default:
		return "inconclusive: review download layer Mbps"
	}
}

func verdictConnectStreamBottleneck(l0, l1, l2, l3 connectStreamBenchResult) string {
	switch {
	case !l0.ok() || !l1.ok() || !l2.ok() || !l3.ok():
		return "FAIL: bench error"
	case l0.mbps < connectStreamLocalizeFastMbps:
		return "L0 raw TCP slow → bench environment or loopback regression"
	case l2.mbps < connectStreamLocalizeFastMbps:
		return "L2 wide-window upload slow → MASQUE path not unlimited (false ceiling suspect)"
	case l1.mbps >= connectStreamLocalizeFastMbps && l3.mbps >= connectStreamLocalizeUploadWindowedMin && l3.mbps <= connectStreamLocalizeUploadWindowedMax:
		return "masque connect-stream bidi: L1 fast, L3 windowed ~64KiB/RTT band → stream credit/RTT on one bidi HTTP/3 leg (not buffer size)"
	case l1.mbps < connectStreamLocalizeFastMbps && l0.mbps >= connectStreamLocalizeFastMbps:
		return "masque connect-stream: L0 fast, L1 slow → tunnel relay or streamConn path (not wire RTT)"
	case l1.mbps >= connectStreamLocalizeFastMbps && l3.mbps > connectStreamLocalizeUploadWindowedMax:
		return "L3 window model did not reproduce ceiling (harness calibration)"
	default:
		return "inconclusive: review layer Mbps"
	}
}

func assertConnectStreamFastLayer(t *testing.T, r connectStreamBenchResult) {
	t.Helper()
	if r.err != nil {
		t.Fatalf("%s: %v", r.layer, r.err)
	}
	if r.mbps < connectStreamLocalizeFastMbps {
		t.Fatalf("%s slow: %.1f Mbit/s (want >= %.0f)", r.layer, r.mbps, connectStreamLocalizeFastMbps)
	}
}

func assertConnectStreamUploadWindowedLayer(t *testing.T, r connectStreamBenchResult) {
	t.Helper()
	if r.err != nil {
		t.Fatalf("%s: %v", r.layer, r.err)
	}
	if r.mbps < connectStreamLocalizeUploadWindowedMin || r.mbps > connectStreamLocalizeUploadWindowedMax {
		t.Fatalf("%s windowed upload: %.1f Mbit/s (want %.0f–%.0f)", r.layer, r.mbps, connectStreamLocalizeUploadWindowedMin, connectStreamLocalizeUploadWindowedMax)
	}
}

func assertConnectStreamDownloadKPILayer(t *testing.T, r connectStreamBenchResult) {
	t.Helper()
	assertConnectStreamWindowedCeilingBand(t, r.mbps, r.layer+" download WriteTo")
}
