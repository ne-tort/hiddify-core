//go:build masque_inttest_heavy

package inttest_test

import (
	"testing"

	masque "github.com/sagernet/sing-box/transport/masque"
	"golang.org/x/net/http2"
)

func TestMasqueConnectStreamH2LocalizeUpload(t *testing.T) {
	dur := masque.InttestLocalizeBenchDuration()
	instant := masque.InttestBenchConnectStreamH2UploadLayer(t, "L1", "instant", dur)
	windowed := masque.InttestBenchConnectStreamH2UploadLayer(t, "L3", "windowed", dur)
	for _, r := range []masque.InttestConnectStreamBenchResult{instant, windowed} {
		if r.Err != nil {
			t.Fatalf("%s upload: %v", r.Layer, r.Err)
		}
		t.Logf("h2 connect-stream upload %s: %.1f Mbit/s (%d bytes)", r.Layer, r.Mbps, r.Bytes)
	}
	if instant.Mbps < masque.InttestConnectStreamLocalizeFastMbps() {
		t.Fatalf("h2 upload instant slow: %.1f Mbit/s (want >= %.0f)", instant.Mbps, masque.InttestConnectStreamLocalizeFastMbps())
	}
	if windowed.Mbps < masque.InttestConnectStreamLocalizeUploadWindowedMin() || windowed.Mbps > masque.InttestConnectStreamLocalizeUploadWindowedMax() {
		t.Fatalf("h2 upload windowed: %.1f Mbit/s (want %.0f–%.0f)", windowed.Mbps, masque.InttestConnectStreamLocalizeUploadWindowedMin(), masque.InttestConnectStreamLocalizeUploadWindowedMax())
	}
}

func TestMasqueConnectStreamH2InstantDownloadExceedsVPSKPI(t *testing.T) {
	dur := masque.InttestLocalizeBenchDuration()
	r := masque.InttestBenchConnectStreamH2DownloadLayerWriteTo(t, "L1", "instant", dur)
	if r.Err != nil {
		t.Fatalf("h2 instant WriteTo download: %v", r.Err)
	}
	t.Logf("h2 connect-stream instant WriteTo download: %.1f Mbit/s", r.Mbps)
	if r.Mbps <= masque.InttestConnectStreamVPSKPITargetDownMbps() {
		t.Fatalf("h2 instant WriteTo download %.1f Mbit/s (want > %.0f VPS KPI)", r.Mbps, masque.InttestConnectStreamVPSKPITargetDownMbps())
	}
}

func TestMasqueConnectStreamH2LocalizeBottleneck(t *testing.T) {
	dur := masque.InttestLocalizeBenchDuration()
	l0 := masque.InttestBenchConnectStreamH2UploadLayer(t, "L0", "", dur)
	l1 := masque.InttestBenchConnectStreamH2UploadLayer(t, "L1", "instant", dur)
	l2 := masque.InttestBenchConnectStreamH2UploadLayer(t, "L2", "wide", dur)
	l3 := masque.InttestBenchConnectStreamH2UploadLayer(t, "L3", "windowed", dur)
	for _, r := range []masque.InttestConnectStreamBenchResult{l0, l1, l2, l3} {
		if r.Err != nil {
			t.Fatalf("%s: %v", r.Layer, r.Err)
		}
		t.Logf("h2 connect-stream localize %s upload: %.1f Mbit/s (%d bytes)", r.Layer, r.Mbps, r.Bytes)
	}
	if l1.Mbps < masque.InttestConnectStreamLocalizeFastMbps() {
		t.Fatalf("h2 L1 upload slow: %.1f Mbit/s (want >= %.0f)", l1.Mbps, masque.InttestConnectStreamLocalizeFastMbps())
	}
	if l3.Mbps < masque.InttestConnectStreamLocalizeUploadWindowedMin() || l3.Mbps > masque.InttestConnectStreamLocalizeUploadWindowedMax() {
		t.Fatalf("h2 L3 upload windowed: %.1f Mbit/s (want %.0f–%.0f)", l3.Mbps, masque.InttestConnectStreamLocalizeUploadWindowedMin(), masque.InttestConnectStreamLocalizeUploadWindowedMax())
	}
	t.Logf("h2 connect-stream localize verdict: %s", masque.InttestVerdictConnectStreamBottleneck(l0, l1, l2, l3))
	dl := masque.InttestBenchConnectStreamH2DownloadLayerWriteTo(t, "L1", "instant", dur)
	if dl.Err != nil {
		t.Fatalf("h2 L1 WriteTo download: %v", dl.Err)
	}
	t.Logf("h2 connect-stream localize L1 WriteTo download: %.1f Mbit/s (%d bytes)", dl.Mbps, dl.Bytes)
	if dl.Mbps < masque.InttestConnectStreamLocalizeFastMbps() {
		t.Fatalf("h2 L1 WriteTo download slow: %.1f Mbit/s (want >= %.0f)", dl.Mbps, masque.InttestConnectStreamLocalizeFastMbps())
	}
}

func TestMasqueConnectStreamH2LocalizeDuplexInstant(t *testing.T) {
	masque.InttestRunConnectStreamH2DuplexWriteToBench(t, "instant", masque.InttestConnectStreamLocalizeFastMbps()/4)
}

func TestMasqueConnectStreamH2LocalizeDownloadWriteTo(t *testing.T) {
	dur := masque.InttestLocalizeBenchDuration()
	instant := masque.InttestBenchConnectStreamH2DownloadLayerWriteTo(t, "L1", "instant", dur)
	windowed := masque.InttestBenchConnectStreamH2DownloadLayerWriteTo(t, "L3", "windowed", dur)
	for _, r := range []masque.InttestConnectStreamBenchResult{instant, windowed} {
		if r.Err != nil {
			t.Fatalf("%s WriteTo download: %v", r.Layer, r.Err)
		}
		t.Logf("h2 connect-stream download %s WriteTo: %.1f Mbit/s (%d bytes)", r.Layer, r.Mbps, r.Bytes)
	}
	if instant.Mbps < masque.InttestConnectStreamLocalizeFastMbps() {
		t.Fatalf("h2 download instant WriteTo slow: %.1f Mbit/s (want >= %.0f)", instant.Mbps, masque.InttestConnectStreamLocalizeFastMbps())
	}
	if windowed.Mbps <= masque.InttestConnectStreamVPSKPITargetDownMbps() {
		t.Fatalf("h2 download windowed WriteTo: %.1f Mbit/s (want > %.0f KPI)", windowed.Mbps, masque.InttestConnectStreamVPSKPITargetDownMbps())
	}
}

func TestMasqueConnectStreamH2LocalizeDuplexWriteTo(t *testing.T) {
	masque.InttestRunConnectStreamH2DuplexWriteToBench(t, "windowed", masque.InttestConnectStreamLocalizeDownloadKPIMin()/2)
}

func TestH2B0WindowedDuplexWriteToNoUploadPulse(t *testing.T) {
	masque.InttestRunConnectStreamH2DuplexWriteToNoPulseBenchMbpsProd(t, masque.InttestConnectStreamVPSKPITargetDownMbps(), 0)
}

func TestH2StrictWindowCeilingBand(t *testing.T) {
	http2.SetMasqueDownloadEagerWindowEnabled(false)
	t.Cleanup(func() { http2.SetMasqueDownloadEagerWindowEnabled(true) })
	masque.InttestRunConnectStreamH2DuplexWriteToNoPulseBenchMbpsStrict(t, 10, 20)
}

func TestH2BidiFlushWakeAfterP1c(t *testing.T) {
	masque.InttestRunConnectStreamH2DuplexWriteToNoPulseBenchMbpsProd(t, masque.InttestConnectStreamVPSKPITargetDownMbps(), 0)
}

func TestH2WindowedDuplexWriteToNoUploadPulse(t *testing.T) {
	masque.InttestRunConnectStreamH2DuplexWriteToNoPulseBenchMbpsProd(t, masque.InttestConnectStreamVPSKPITargetDownMbps(), 0)
}
