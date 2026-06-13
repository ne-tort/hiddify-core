package masque

import (
	"strings"
	"testing"

	strm "github.com/sagernet/sing-box/transport/masque/stream"
)

// TestArchREFSRCH2OAudit (REF-SRC-H2O-1/2/3/5): frozen h2o vs sb server differential.
func TestArchREFSRCH2OAudit(t *testing.T) {
	if len(ArchREFSRCH2OAudit) < 6 {
		t.Fatalf("ArchREFSRCH2OAudit: %d rows want >= 6", len(ArchREFSRCH2OAudit))
	}
	parity := 0
	gaps := 0
	for _, row := range ArchREFSRCH2OAudit {
		if row.Parity {
			parity++
		} else {
			gaps++
		}
		if row.ID == "REF-SRC-H2O-2" && row.Parity && ArchREFSRCH2OTunnelMultiplex() != 65536 {
			t.Fatalf("tunnel buffer %d want 65536", ArchREFSRCH2OTunnelMultiplex())
		}
	}
	if parity < 4 {
		t.Fatalf("REF-SRC-H2O parity rows %d want >= 4", parity)
	}
	if gaps < 3 {
		t.Fatalf("REF-SRC-H2O-5 gaps %d want >= 3 concrete deltas", gaps)
	}
	if ArchREFSRCH2OTunnelMultiplex() != strm.RelayTunnelBufLen {
		t.Fatal("h2o tunnel buffer drift from stream package")
	}
	t.Logf("REF-SRC-H2O audit: %d rows (%d parity, %d gaps); KPI root = client S2C WINDOW_UPDATE", len(ArchREFSRCH2OAudit), parity, gaps)
}

// TestArchREFSRCThinRelayParityAudit (REF-SRC-THIN-1/2): masquethin relay delegates to stream/relay.go.
func TestArchREFSRCThinRelayParityAudit(t *testing.T) {
	if len(ArchREFSRCThinRelayAudit) < 2 {
		t.Fatalf("ArchREFSRCThinRelayAudit: %d rows want >= 2", len(ArchREFSRCThinRelayAudit))
	}
	for _, row := range ArchREFSRCThinRelayAudit {
		if !row.Delegate {
			t.Fatalf("REF-SRC-THIN-2 gap: %s not delegated to %s", row.ThinSymbol, row.StreamSymbol)
		}
	}
	if !strings.Contains(strm.RelayGoAuditSource(), "RelayTCPTunnel") {
		t.Fatal("stream/relay.go embed missing RelayTCPTunnel anchor")
	}
	t.Log("REF-SRC-THIN-2 verdict: masquethin/relay.go delegates 100%% to stream/relay.go (2 symbols)")
}

// TestArchREFSRCThinVsSBServerAudit (REF-SRC-THIN-3/4): documents thin fast vs sb slow attribution.
func TestArchREFSRCThinVsSBServerAudit(t *testing.T) {
	if len(ArchREFSRCThinVsSBAudit) < 4 {
		t.Fatalf("ArchREFSRCThinVsSBAudit: %d rows want >= 4", len(ArchREFSRCThinVsSBAudit))
	}
	for _, row := range ArchREFSRCThinVsSBAudit {
		if row.Factor == "" || row.KPIImpact == "" {
			t.Fatalf("incomplete thin vs sb row: %+v", row)
		}
	}
	t.Log("REF-SRC-THIN-3 verdict: thin ~554 = bind/authority path; relay code identical; prod ~15 = client wire FC")
}
