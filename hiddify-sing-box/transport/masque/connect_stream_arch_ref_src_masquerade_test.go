package masque

import (
	"strings"
	"testing"

	"github.com/sagernet/sing-box/transport/masque/h3"
)

// TestArchREFSRCMasqueradeAudit (REF-SRC-MASQ-1/2/3): frozen masquerade quiche vs sb/quic-go differential.
func TestArchREFSRCMasqueradeAudit(t *testing.T) {
	if len(ArchREFSRCMasqueradeAudit) < 8 {
		t.Fatalf("ArchREFSRCMasqueradeAudit: %d rows want >= 8", len(ArchREFSRCMasqueradeAudit))
	}
	byID := map[string]ArchREFSRCMasqueradeRow{}
	parity, mapped, skip := 0, 0, 0
	for _, row := range ArchREFSRCMasqueradeAudit {
		if row.ID == "" || row.Anchor == "" || row.PortAction == "" {
			t.Fatalf("incomplete REF-SRC-MASQ row: %+v", row)
		}
		byID[row.ID] = row
		if row.Parity {
			parity++
		}
		switch row.PortAction {
		case "mapped":
			mapped++
		case "skip":
			skip++
		default:
			t.Fatalf("unknown PortAction %q on %s", row.PortAction, row.ID)
		}
	}
	for _, id := range []string{
		"REF-SRC-MASQ-1-scheduler",
		"REF-SRC-MASQ-1-stream-blocked",
		"REF-SRC-MASQ-2-connect-branch",
		"REF-SRC-MASQ-3-verdict",
	} {
		if _, ok := byID[id]; !ok {
			t.Fatalf("missing REF-SRC-MASQ row %s", id)
		}
	}
	if parity < 6 {
		t.Fatalf("REF-SRC-MASQ parity rows %d want >= 6", parity)
	}
	if mapped < 5 {
		t.Fatalf("REF-SRC-MASQ mapped port actions %d want >= 5", mapped)
	}
	if skip < 2 {
		t.Fatalf("REF-SRC-MASQ skip port actions %d want >= 2", skip)
	}
	verdict := ArchMasqueradeSchedulingPortVerdict()
	if !strings.Contains(verdict, "no-port") {
		t.Fatalf("MASQ-3 verdict want no-port: %q", verdict)
	}
	if !strings.Contains(archRelayGoAuditSource(), "relayTCPTunnelBidiStream") {
		t.Fatal("stream/relay.go missing relayTCPTunnelBidiStream anchor for MASQ-2 parity")
	}
	if h3.BidiDuplexCoordEnabled() {
		t.Fatal("prod must not use duplex_coord")
	}
	t.Logf("REF-SRC-MASQ audit: %d rows (%d parity, %d mapped, %d skip); verdict=%q",
		len(ArchREFSRCMasqueradeAudit), parity, mapped, skip, verdict)
}
