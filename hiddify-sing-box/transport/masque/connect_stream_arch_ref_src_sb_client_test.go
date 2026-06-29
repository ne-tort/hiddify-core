package masque

import (
	"testing"

	"github.com/sagernet/sing-box/transport/masque/h3"
)

// TestArchREFSRCSBClientAudit (REF-SRC-SB-C1/C2): frozen TunnelConn vs Invisv differential + non-RFC table.
func TestArchREFSRCSBClientAudit(t *testing.T) {
	if len(ArchREFSRCSBClientAudit) < 5 {
		t.Fatalf("ArchREFSRCSBClientAudit: %d rows want >= 5", len(ArchREFSRCSBClientAudit))
	}
	gaps := 0
	for _, row := range ArchREFSRCSBClientAudit {
		if row.Attr == "" || row.Invisv == "" || row.SB == "" {
			t.Fatalf("incomplete client audit row: %+v", row)
		}
		if !row.Parity {
			gaps++
		}
	}
	if gaps != 1 {
		t.Fatalf("REF-SRC-SB-C1 gaps %d want 1 (duplex_coord only)", gaps)
	}
	if len(ArchREFSRCSBClientNonRFC) < 8 {
		t.Fatalf("ArchREFSRCSBClientNonRFC: %d rows want >= 8", len(ArchREFSRCSBClientNonRFC))
	}
	for _, row := range ArchREFSRCSBClientNonRFC {
		if row.Layer == "" || row.Action == "" {
			t.Fatalf("incomplete non-RFC row: %+v", row)
		}
	}
	if h3.CurrentConnectStreamMode() != h3.ConnectStreamModeSingleBidi {
		t.Fatal("REF-SRC-SB-C2: prod must use nil Body (pipe off)")
	}
	t.Log("REF-SRC-SB-C1/C2 verdict: h3_stream prod default; pipe/feeder opt-in legacy; duplex_coord keep")
}

// TestArchREFSRCSBClientC3PeerAttribution (REF-SRC-SB-C3): same client harness, h2o-peer vs windowed sb-peer.
func TestArchREFSRCSBClientC3PeerAttribution(t *testing.T) {
	const duration = localizeBenchDuration

	sbMbps, _, err := benchBypassRowDownloadMbps(benchWindowedBidiLink(), duration)
	if err != nil {
		t.Fatalf("sb-peer windowed: %v", err)
	}
	if sbMbps <= connectStreamVPSKPITargetDownMbps {
		t.Fatalf("sb-peer %.1f Mbit/s (want > %.0f K-S1)", sbMbps, connectStreamVPSKPITargetDownMbps)
	}

	h2oMbps, _, err := benchBypassRowDownloadMbps(bypassB2BidiLink(), duration)
	if err != nil {
		t.Fatalf("h2o-peer: %v", err)
	}
	if h2oMbps <= connectStreamVPSKPITargetDownMbps {
		t.Fatalf("h2o-peer %.1f Mbit/s (want > %.0f)", h2oMbps, connectStreamVPSKPITargetDownMbps)
	}
	t.Logf("REF-SRC-SB-C3: sb=%.1f h2o=%.1f — peer swap both >21", sbMbps, h2oMbps)
}

// TestArchREFSRCSBClientProdBenchLink (REF-SRC-SB-C1): windowed bench uses eager S2C when default env on.
func TestArchREFSRCSBClientProdBenchLink(t *testing.T) {
	link := benchWindowedBidiLink()
	if h3.DownloadEagerWindowEnabled() && !link.instantCreditS2C {
		t.Fatal("benchWindowedBidiLink must set instantCreditS2C with default eager window")
	}
}
