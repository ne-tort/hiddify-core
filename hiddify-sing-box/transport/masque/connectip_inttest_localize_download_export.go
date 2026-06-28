package masque

import "testing"

func InttestMasqueConnectIPLocalizeDownload(t *testing.T) {
	t.Helper()
	const dur = localizeBenchDuration
	l0 := benchConnectIPDownloadLayer(t, "L0", instantPacketLink{}, dur)
	l1 := benchConnectIPDownloadLayer(t, "L1-prod", prodInstantPacketLink{}, dur)
	l3 := benchConnectIPDownloadLayer(t, "L3-windowed", benchWindowedPacketLink(), dur)
	t.Logf("connect-ip download localize: L0=%.1f L1=%.1f L3=%.1f Mbit/s", l0.mbps, l1.mbps, l3.mbps)
	t.Log(verdictConnectIPDownload(l0, l1, l3))
	if !l1.ok() || l1.mbps < 1.0 {
		t.Fatalf("L1 download dead: %v (%.1f Mbit/s)", l1.err, l1.mbps)
	}
}

func InttestConnectIPLocalizeForwarderDownloadWindowedWriteTo(t *testing.T) {
	t.Helper()
	gateConnectIPTCPForwarderDownloadWindowedLinkThroughput(t)
}

func InttestConnectIPForwarderDownloadWindowedBand(t *testing.T) {
	t.Helper()
	gateConnectIPTCPForwarderDownloadWindowedLinkThroughput(t)
}

func InttestWindowedPacketBridgeDownloadBand(t *testing.T) {
	t.Helper()
	gateConnectIPTCPForwarderDownloadWindowedLinkThroughput(t)
}

func InttestLocalizeConnectIPNativeH3PipeL1Reference(t *testing.T) {
	t.Helper()
	r := benchConnectIPUploadLayerBest(t, "L1-prod", prodInstantPacketLink{}, localizeBenchDuration, 3)
	if r.err != nil {
		t.Fatalf("native pipe L1 reference: %v", r.err)
	}
	t.Logf("native H3 pipe L1 reference: %.1f Mbit/s", r.mbps)
	if r.mbps < 1.0 {
		t.Fatalf("pipe L1 dead: %.1f Mbit/s", r.mbps)
	}
}
