package masque

import (
	"testing"
)

// TestArchREFSRCInvisvAudit (REF-SRC-INVISV-1…4): frozen Invisv vs sing-box client differential.
func TestArchREFSRCInvisvAudit(t *testing.T) {
	if len(ArchREFSRCInvisvAudit) < 4 {
		t.Fatalf("ArchREFSRCInvisvAudit: %d rows want >= 4", len(ArchREFSRCInvisvAudit))
	}
	seen := map[string]bool{}
	for _, row := range ArchREFSRCInvisvAudit {
		if row.ID == "" || row.Attr == "" {
			t.Fatalf("incomplete row: %+v", row)
		}
		if seen[row.ID] {
			t.Fatalf("duplicate ID %s", row.ID)
		}
		seen[row.ID] = true
	}
	for _, id := range []string{"REF-SRC-INVISV-1", "REF-SRC-INVISV-2", "REF-SRC-INVISV-3", "REF-SRC-INVISV-4"} {
		if !seen[id] {
			t.Fatalf("missing %s", id)
		}
	}
	t.Logf("REF-SRC-INVISV audit: %d rows — %s", len(ArchREFSRCInvisvAudit), ArchREFSRCInvisvVerdict)
}

// TestArchREFSRCInvisvProdKPI (REF-SRC-INVISV-2/4): prod bench link exceeds VPS KPI when eager WINDOW on;
// Invisv upstream quic-go uses stock 0.05 threshold — our patch is the KPI unlock, not Invisv fork alone.
func TestArchREFSRCInvisvProdKPI(t *testing.T) {
	h := startConnectStreamDownloadHarness(t, benchWindowedBidiLink())
	defer h.close()
	_, mbps, err := measureTCPDownloadWriteToMbps(h.conn, localizeBenchDuration)
	if err != nil {
		t.Fatalf("prod windowed WriteTo: %v", err)
	}
	t.Logf("REF-SRC-INVISV prod KPI: %.1f Mbit/s (Invisv thin + our eager WINDOW)", mbps)
	if mbps <= connectStreamVPSKPITargetDownMbps {
		t.Fatalf("prod eager window %.1f Mbit/s want > %.0f", mbps, connectStreamVPSKPITargetDownMbps)
	}
}
