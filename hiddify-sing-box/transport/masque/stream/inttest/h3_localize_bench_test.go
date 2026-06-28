package inttest_test

import (
	"testing"

	masque "github.com/sagernet/sing-box/transport/masque"
)

func TestMasqueConnectStreamLocalizeUpload(t *testing.T) {
	dur := masque.InttestLocalizeBenchDuration()
	instant := masque.InttestBenchConnectStreamUploadLayer(t, "L1", "instant", dur)
	windowed := masque.InttestBenchConnectStreamUploadLayer(t, "L3", "windowed", dur)
	for _, r := range []masque.InttestConnectStreamBenchResult{instant, windowed} {
		if r.Err != nil {
			t.Fatalf("%s upload: %v", r.Layer, r.Err)
		}
		t.Logf("connect-stream upload %s: %.1f Mbit/s (%d bytes)", r.Layer, r.Mbps, r.Bytes)
	}
	masque.InttestAssertConnectStreamFastLayer(t, instant)
	masque.InttestAssertConnectStreamUploadWindowedLayer(t, windowed)
}

func TestMasqueConnectStreamLocalizeDownloadWriteTo(t *testing.T) {
	dur := masque.InttestLocalizeBenchDuration()
	instant := masque.InttestBenchConnectStreamDownloadLayerWriteTo(t, "L1", "instant", dur)
	windowed := masque.InttestBenchConnectStreamDownloadLayerWriteTo(t, "L3", "windowed", dur)
	for _, r := range []masque.InttestConnectStreamBenchResult{instant, windowed} {
		if r.Err != nil {
			t.Fatalf("%s WriteTo download: %v", r.Layer, r.Err)
		}
		t.Logf("connect-stream download %s WriteTo: %.1f Mbit/s (%d bytes)", r.Layer, r.Mbps, r.Bytes)
	}
	masque.InttestAssertConnectStreamFastLayer(t, instant)
	masque.InttestAssertConnectStreamDownloadKPILayer(t, windowed)
}

func TestMasqueConnectStreamLocalizeBottleneck(t *testing.T) {
	dur := masque.InttestLocalizeBenchDuration()
	l0 := masque.InttestBenchConnectStreamUploadLayer(t, "L0", "", dur)
	l1 := masque.InttestBenchConnectStreamUploadLayer(t, "L1", "instant", dur)
	l2 := masque.InttestBenchConnectStreamUploadLayer(t, "L2", "wide", dur)
	l3 := masque.InttestBenchConnectStreamUploadLayer(t, "L3", "windowed", dur)
	for _, r := range []masque.InttestConnectStreamBenchResult{l0, l1, l2, l3} {
		if r.Err != nil {
			t.Fatalf("%s: %v", r.Layer, r.Err)
		}
		t.Logf("connect-stream localize %s upload: %.1f Mbit/s (%d bytes)", r.Layer, r.Mbps, r.Bytes)
	}
	masque.InttestAssertConnectStreamFastLayer(t, l1)
	masque.InttestAssertConnectStreamUploadWindowedLayer(t, l3)
	t.Logf("connect-stream localize verdict: %s", masque.InttestVerdictConnectStreamBottleneck(l0, l1, l2, l3))

	dl0 := masque.InttestBenchConnectStreamDownloadLayerWriteTo(t, "L0", "", dur)
	dl1 := masque.InttestBenchConnectStreamDownloadLayerWriteTo(t, "L1", "instant", dur)
	dl3 := masque.InttestBenchConnectStreamDownloadLayerWriteTo(t, "L3", "windowed", dur)
	for _, r := range []masque.InttestConnectStreamBenchResult{dl0, dl1, dl3} {
		if r.Err != nil {
			t.Fatalf("%s WriteTo download: %v", r.Layer, r.Err)
		}
		t.Logf("connect-stream localize %s download WriteTo: %.1f Mbit/s (%d bytes)", r.Layer, r.Mbps, r.Bytes)
	}
	masque.InttestAssertConnectStreamFastLayer(t, dl1)
	masque.InttestAssertConnectStreamDownloadKPILayer(t, dl3)
	t.Logf("connect-stream localize download verdict: %s", masque.InttestVerdictConnectStreamDownload(dl0, dl1, dl3))
}

func TestMasqueConnectStreamLocalizeDuplexInstant(t *testing.T) {
	masque.InttestRunConnectStreamDuplexWriteToBench(t, "instant", masque.InttestConnectStreamLocalizeFastMbps()/4)
}

func TestMasqueConnectStreamLocalizeDuplexWriteTo(t *testing.T) {
	masque.InttestRunConnectStreamDuplexWriteToBench(t, "windowed", masque.InttestConnectStreamLocalizeDownloadKPIMin()/2)
}

func TestConnectStreamLegsVsSaturatedDuplexDiagnostic(t *testing.T) {
	dur := masque.InttestLocalizeBenchDuration()
	link := "windowed"

	downConn, downClose := masque.InttestStartConnectStreamDownloadHarness(t, link)
	defer downClose()
	_, downLeg, err := masque.InttestMeasureTCPDownloadWriteToMbps(downConn, dur)
	if err != nil {
		t.Fatalf("download leg: %v", err)
	}

	upConn, upClose := masque.InttestStartConnectStreamDownloadHarness(t, link)
	defer upClose()
	_, upLeg, err := masque.InttestMeasureTCPUploadMbps(upConn, dur)
	if err != nil {
		t.Fatalf("upload leg: %v", err)
	}

	dupConn, dupClose := masque.InttestStartConnectStreamDownloadHarness(t, link)
	defer dupClose()
	dupDown, dupUp, dupMin, err := masque.InttestMeasureSegmentDuplexMbps(dupConn, dur)
	if err != nil {
		t.Fatalf("saturated duplex: %v", err)
	}

	t.Logf("legs vs saturated duplex (windowed, %s): down_leg=%.1f up_leg=%.1f | duplex down=%.1f up=%.1f min=%.1f | duplex/leg down=%.2f up=%.2f",
		dur, downLeg, upLeg, dupDown, dupUp, dupMin, dupDown/downLeg, dupUp/upLeg)
}
