package masque

import (
	"testing"

	"github.com/sagernet/sing-box/transport/masque/h3"
)

// TestArchREF3InvisvHTTPStreamerAudit (REF3-1): frozen Invisv CreateTCPStream vs thin CONNECT-stream dial.
func TestArchREF3InvisvHTTPStreamerAudit(t *testing.T) {
	if len(ArchInvisvThinAudit) < 5 {
		t.Fatalf("ArchInvisvThinAudit: %d rows want >= 5", len(ArchInvisvThinAudit))
	}
	for _, row := range ArchInvisvThinAudit {
		if !row.Parity {
			t.Fatalf("REF3-1 gap %s: invisv=%s thin=%s", row.Attr, row.Invisv, row.Thin)
		}
	}
	t.Setenv("MASQUE_CONNECT_STREAM_THIN", "1")
	if h3.ConnectStreamUsePipeUpload() {
		t.Fatal("thin mode must disable pipe upload")
	}
	if h3.BidiDuplexCoordEnabled() {
		t.Fatal("thin mode must disable duplex_coord")
	}
	if h3.TunnelWriteToBufLen() != 64*1024 {
		t.Fatalf("thin WriteTo buf=%d want 65536", h3.TunnelWriteToBufLen())
	}
	t.Logf("REF3-1 audit: %d Invisv parity rows; thin env forces h3_stream + direct WriteTo", len(ArchInvisvThinAudit))
}

// TestArchREF3ThinDialKPI (REF3-4): MASQUE_CONNECT_STREAM_THIN on L3 harness — instant >21,
// windowed sb-peer stays in FC band (client thin path does not unlock connect-stream-h3 KPI alone).
func TestArchREF3ThinDialKPI(t *testing.T) {
	const duration = localizeBenchDuration
	t.Setenv("MASQUE_CONNECT_STREAM_THIN", "1")

	instantH := startConnectStreamDownloadHarness(t, instantBidiLink{}, connectStreamHarnessOpts{Thin: true})
	defer instantH.close()
	n, instantMbps, err := measureTCPDownloadWriteToMbps(instantH.conn, duration)
	if err != nil {
		t.Fatalf("thin instant: %v", err)
	}
	t.Logf("REF3-4 thin instant: %.1f Mbit/s (%d bytes)", instantMbps, n)
	if instantMbps <= connectStreamVPSKPITargetDownMbps {
		t.Fatalf("thin instant %.1f Mbit/s (want > %.0f)", instantMbps, connectStreamVPSKPITargetDownMbps)
	}

	windowedH := startConnectStreamDownloadHarness(t, benchWindowedBidiLink(), connectStreamHarnessOpts{Thin: true})
	defer windowedH.close()
	_, windowedMbps, err := measureTCPDownloadWriteToMbps(windowedH.conn, duration)
	if err != nil {
		t.Fatalf("thin windowed: %v", err)
	}
	t.Logf("REF3-4 thin windowed sb-peer: %.1f Mbit/s", windowedMbps)
	assertConnectStreamWindowedCeilingBand(t, windowedMbps, "REF3-4 thin windowed")
	t.Log("REF3-4 verdict: thin Invisv dial >21 on instant; sb-peer ceiling = wire FC not client wrap")
}

// TestArchREF3ThinModeSBServerAB (REF3-3): A/B prod vs MASQUE_CONNECT_STREAM_THIN through sb server
// relay (HandleTCPConnectRequest); windowed sb-peer ceiling unchanged — thin client does not unlock connect-stream-h3 KPI.
func TestArchREF3ThinModeSBServerAB(t *testing.T) {
	const duration = localizeBenchDuration

	prodH := startConnectStreamDownloadHarness(t, benchWindowedBidiLink())
	defer prodH.close()
	_, prodMbps, err := measureTCPDownloadWriteToMbps(prodH.conn, duration)
	if err != nil {
		t.Fatalf("prod windowed: %v", err)
	}
	assertConnectStreamWindowedCeilingBand(t, prodMbps, "REF3-3 prod sb server")

	thinH := startConnectStreamDownloadHarness(t, benchWindowedBidiLink(), connectStreamHarnessOpts{Thin: true})
	defer thinH.close()
	_, thinMbps, err := measureTCPDownloadWriteToMbps(thinH.conn, duration)
	if err != nil {
		t.Fatalf("thin windowed: %v", err)
	}
	assertConnectStreamWindowedCeilingBand(t, thinMbps, "REF3-3 thin sb server")

	delta := prodMbps - thinMbps
	if delta < 0 {
		delta = -delta
	}
	if delta > 3.0 {
		t.Fatalf("REF3-3 A/B delta %.1f Mbit/s too large (prod=%.1f thin=%.1f); thin must not move sb-peer ceiling",
			delta, prodMbps, thinMbps)
	}
	t.Logf("REF3-3 A/B sb server: prod=%.1f thin=%.1f Mbit/s (delta=%.1f); verdict: client thin path not KPI root",
		prodMbps, thinMbps, delta)
}

// TestArchREF3MasqueradeStreamBlockedAudit (REF3-2): frozen masquerade quiche loop vs sb/quic-go;
// StreamBlocked semantic parity on CONNECT nil-body; scheduler/relay gaps documented, not KPI root.
func TestArchREF3MasqueradeStreamBlockedAudit(t *testing.T) {
	if len(ArchMasqueradeStreamBlockedAudit) < 5 {
		t.Fatalf("ArchMasqueradeStreamBlockedAudit: %d rows want >= 5", len(ArchMasqueradeStreamBlockedAudit))
	}
	parityCount := 0
	for _, row := range ArchMasqueradeStreamBlockedAudit {
		if row.Parity {
			parityCount++
		}
	}
	if parityCount < 3 {
		t.Fatalf("REF3-2 parity rows %d want >= 3 (StreamBlocked + CONNECT upload + download)", parityCount)
	}
	t.Setenv("MASQUE_CONNECT_STREAM_THIN", "1")
	if h3.ConnectStreamUsePipeUpload() {
		t.Fatal("thin path must disable pipe upload (masquerade minimal depth)")
	}
	if h3.BidiDuplexCoordEnabled() {
		t.Fatal("thin path must disable duplex_coord (masquerade direct stream copy)")
	}
	t.Logf("REF3-2 audit: %d masquerade rows (%d parity); KPI ceiling = wire S2C FC (REF2-2) not retry queue alone",
		len(ArchMasqueradeStreamBlockedAudit), parityCount)
}
