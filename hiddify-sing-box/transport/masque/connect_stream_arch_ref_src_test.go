package masque

import (
	"strings"
	"testing"

	"github.com/sagernet/sing-box/transport/masque/connectip"
	"github.com/sagernet/sing-box/transport/masque/h3"
	strm "github.com/sagernet/sing-box/transport/masque/stream"
)

func auditSourceContains(t *testing.T, name, source string, needles []string) {
	t.Helper()
	for _, needle := range needles {
		if !strings.Contains(source, needle) {
			t.Fatalf("%s embed audit: missing %q", name, needle)
		}
	}
}

// TestArchREFSRCEmbedInvisvSource verifies frozen Invisv needles in h3 prod sources.
func TestArchREFSRCEmbedInvisvSource(t *testing.T) {
	src := h3.ConnectRequestAuditSource() + h3.TunnelConnAuditSource() + h3.TunnelFromResponseAuditSource()
	auditSourceContains(t, "Invisv", src, ArchREFSRCInvisvSourceNeedles)
}

// TestArchREFSRCEmbedH2oSource verifies frozen h2o relay needles in stream/relay.go.
func TestArchREFSRCEmbedH2oSource(t *testing.T) {
	auditSourceContains(t, "h2o", strm.RelayGoAuditSource(), ArchREFSRCH2oAudit)
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
