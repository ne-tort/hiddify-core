package masque

import (
	"testing"

	strm "github.com/sagernet/sing-box/transport/masque/stream"
)

// TestArchREFSRCServerCallChainAudit (REF-SRC-SB-1): frozen server CONNECT-stream call chain.
func TestArchREFSRCServerCallChainAudit(t *testing.T) {
	if len(ArchREFSRCServerCallChain) < 5 {
		t.Fatalf("ArchREFSRCServerCallChain: %d rows want >= 5", len(ArchREFSRCServerCallChain))
	}
	for _, row := range ArchREFSRCServerCallChain {
		if !row.Parity {
			t.Fatalf("REF-SRC-SB-1 gap %s: %s → %s", row.Layer, row.Symbol, row.Next)
		}
	}
	t.Logf("REF-SRC-SB-1 audit: %d hops mux → HandleTCPConnectRequest → RelayTCPTunnel", len(ArchREFSRCServerCallChain))
}

// TestArchREFSRCServerUploadAudit (REF-SRC-SB-4): default tunnel upload 64 KiB matches h2o; legacy is opt-in.
func TestArchREFSRCServerUploadAudit(t *testing.T) {
	if len(ArchREFSRCServerUploadAudit) < 3 {
		t.Fatalf("ArchREFSRCServerUploadAudit: %d rows want >= 3", len(ArchREFSRCServerUploadAudit))
	}
	for _, row := range ArchREFSRCServerUploadAudit {
		if row.Path == "H3 hijack default" && row.Chunk != ArchH2OParityRelayBufLen() {
			t.Fatalf("default upload chunk %d want h2o %d", row.Chunk, ArchH2OParityRelayBufLen())
		}
		if row.Path == "Legacy flush relay" && row.H2OParity {
			t.Fatal("legacy upload must not claim h2o parity")
		}
	}
	t.Log("REF-SRC-SB-4 verdict: prod upload = 64 KiB stream hijack; legacy 512 KiB not default")
}

// TestArchREFSRCServerDownloadAudit (REF-SRC-SB-5): H3 download boost + H2 flush batch documented.
func TestArchREFSRCServerDownloadAudit(t *testing.T) {
	if len(ArchREFSRCServerDownloadAudit) < 2 {
		t.Fatalf("ArchREFSRCServerDownloadAudit: %d rows want >= 2", len(ArchREFSRCServerDownloadAudit))
	}
	for _, row := range ArchREFSRCServerDownloadAudit {
		if !row.H2OParity {
			t.Fatalf("REF-SRC-SB-5 gap %s", row.Path)
		}
	}
	if ArchH2OParityRelayFlushBytes() != strm.RelayTunnelFlushBytes {
		t.Fatal("H2 flush audit drift from stream package")
	}
	t.Log("REF-SRC-SB-5 verdict: H3 MasqueSetBidiDownloadActive on server download; H2 64 KiB flush batch")
}

// TestArchREFSRCServerThinAudit (REF-SRC-SB-2/3): ServerEndpoint / thin / ServerThin share relay entry.
func TestArchREFSRCServerThinAudit(t *testing.T) {
	if len(ArchREFSRCServerThinAudit) < 4 {
		t.Fatalf("ArchREFSRCServerThinAudit: %d rows want >= 4", len(ArchREFSRCServerThinAudit))
	}
	for _, row := range ArchREFSRCServerThinAudit {
		if !row.Parity {
			t.Fatalf("REF-SRC-SB-2/3 gap %s", row.Flag)
		}
	}
	t.Log("REF-SRC-SB-2/3 verdict: endpoint wrap delegates only; thin flags gate mux not relay shape")
}

// TestArchREFSRCServerRelayKPIAudit (REF-SRC-SB-6): h2o-parity relay instant >21; windowed FC band documented.
func TestArchREFSRCServerRelayKPIAudit(t *testing.T) {
	const duration = localizeBenchDuration

	instant := benchRelayH3Download(t, instantBidiLink{}, duration)
	if instant.err != nil {
		t.Fatalf("instant relay: %v", instant.err)
	}
	if instant.mbps <= connectStreamVPSKPITargetDownMbps {
		t.Fatalf("REF-SRC-SB-6 instant %.1f Mbit/s want > %.0f after h2o-parity patch", instant.mbps, connectStreamVPSKPITargetDownMbps)
	}

	windowed := benchRelayH3Download(t, benchWindowedBidiLink(), duration)
	if windowed.err != nil {
		t.Fatalf("windowed relay: %v", windowed.err)
	}
	assertConnectStreamWindowedCeilingBand(t, windowed.mbps, "REF-SRC-SB-6 windowed sb-peer")

	if ArchREFSRCServerRelayKPIAudit.Verdict == "" {
		t.Fatal("missing REF-SRC-SB-6 verdict text")
	}
	t.Logf("REF-SRC-SB-6 instant=%.1f windowed=%.1f — %s", instant.mbps, windowed.mbps, ArchREFSRCServerRelayKPIAudit.Verdict)
}
