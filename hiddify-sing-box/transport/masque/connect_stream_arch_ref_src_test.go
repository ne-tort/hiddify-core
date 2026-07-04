package masque

import (
	"strings"
	"testing"

	"github.com/sagernet/sing-box/transport/masque/connectip"
)

func auditSourceContains(t *testing.T, name, source string, needles []string) {
	t.Helper()
	for _, needle := range needles {
		if !strings.Contains(source, needle) {
			t.Fatalf("%s embed audit: missing %q", name, needle)
		}
	}
}

// TestArchREFSRCH2InvisvAuditFrozen locks REF-H2-INVISV differential table for wave-5 ref compare.
func TestArchREFSRCH2InvisvAuditFrozen(t *testing.T) {
	if len(ArchREFSRCH2InvisvAudit) < 7 {
		t.Fatalf("REF-H2-INVISV audit rows=%d want >=7", len(ArchREFSRCH2InvisvAudit))
	}
	if ArchREFSRCH2InvisvVerdict == "" {
		t.Fatal("REF-H2-INVISV verdict empty")
	}
	for _, row := range ArchREFSRCH2InvisvAudit {
		if row.ID == "REF-H2-INV-1" && row.Status != "ADAPT" {
			t.Fatalf("%s status=%s want ADAPT (H8 shallow prod)", row.ID, row.Status)
		}
	}
	t.Log(ArchREFSRCH2InvisvVerdict)
}

// TestArchREFSRCEmbedInvisvSource verifies frozen Invisv needles in h3 prod sources.
func TestArchREFSRCEmbedInvisvSource(t *testing.T) {
	src := archH3InvisvAuditSource()
	auditSourceContains(t, "Invisv", src, ArchREFSRCInvisvSourceNeedles)
}

// TestArchREFSRCEmbedH2oSource verifies frozen h2o relay needles in stream/relay.go.
func TestArchREFSRCEmbedH2oSource(t *testing.T) {
	auditSourceContains(t, "h2o", archRelayGoAuditSource(), ArchREFSRCH2oAudit)
}

// TestArchREFSRCEmbedUsqueSource verifies frozen usque needles in connectip/netstack.go.
func TestArchREFSRCEmbedUsqueSource(t *testing.T) {
	auditSourceContains(t, "usque", connectip.NetstackAuditSource(), ArchREFSRCUsqueSourceNeedles)
	frame := connectip.CloneInboundFrame([]byte{0x45, 0x00, 0x00, 0x1c})
	if len(frame) == 0 {
		t.Fatal("CloneInboundFrame returned empty")
	}
}

// TestArchREFSRCEmbedMasqueradeFrozen verifies frozen masquerade architectural strings.
func TestArchREFSRCEmbedMasqueradeFrozen(t *testing.T) {
	for _, s := range ArchREFSRCMasqueradeFrozen {
		if strings.TrimSpace(s) == "" {
			t.Fatalf("empty masquerade frozen entry")
		}
	}
}
