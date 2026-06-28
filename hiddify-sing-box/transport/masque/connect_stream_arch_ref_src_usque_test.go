package masque

import (
	"strings"
	"testing"

	strm "github.com/sagernet/sing-box/transport/masque/stream"
)

// TestArchREFSRCUsqueAudit (REF-SRC-USQUE-1/2/3): frozen usque CONNECT-IP scope vs connect-stream KPI path.
func TestArchREFSRCUsqueAudit(t *testing.T) {	if len(ArchREFSRCUsqueAudit) < 6 {
		t.Fatalf("ArchREFSRCUsqueAudit: %d rows want >= 6", len(ArchREFSRCUsqueAudit))
	}
	byID := map[string]ArchREFSRCUsqueRow{}
	portable := 0
	nonPortable := 0
	for _, row := range ArchREFSRCUsqueAudit {
		byID[row.ID] = row
		if row.Portable {
			portable++
		} else {
			nonPortable++
		}
	}
	for _, id := range []string{
		"REF-SRC-USQUE-1",
		"REF-SRC-USQUE-2-dataplane",
		"REF-SRC-USQUE-2-maintain",
		"REF-SRC-USQUE-2-cfproto",
		"REF-SRC-USQUE-3-buffer",
		"REF-SRC-USQUE-3-relay",
	} {
		if _, ok := byID[id]; !ok {
			t.Fatalf("missing REF-SRC-USQUE row %s", id)
		}
	}
	if !strings.Contains(byID["REF-SRC-USQUE-1"].Usque, "cf-connect-ip") {
		t.Fatal("REF-SRC-USQUE-1: usque must dial cf-connect-ip not CONNECT-stream")
	}
	if !strings.Contains(byID["REF-SRC-USQUE-1"].SB, "connect_ip") {
		t.Fatal("REF-SRC-USQUE-1: sb warp path must be connect_ip")
	}
	if byID["REF-SRC-USQUE-2-dataplane"].Portable {
		t.Fatal("REF-SRC-USQUE-2: packet plane must not be portable to connect-stream")
	}
	if !byID["REF-SRC-USQUE-3-buffer"].Portable {
		t.Fatal("REF-SRC-USQUE-3: buffer pool pattern should be marked portable (already in sb)")
	}
	if ArchREFSRCUsqueRelayBufLen() != strm.RelayTunnelBufLen || strm.RelayTunnelBufLen != 65536 {
		t.Fatalf("relay buffer drift: audit=%d stream=%d", ArchREFSRCUsqueRelayBufLen(), strm.RelayTunnelBufLen)
	}
	src := archRelayGoAuditSource()
	for _, sym := range []string{"relayTunnelBufPool", "relayTunnelCopyBuffer", "RelayTCPTunnel"} {
		if !strings.Contains(src, sym) {
			t.Fatalf("stream/relay.go embed missing %s (REF-SRC-USQUE-3)", sym)
		}
	}
	if nonPortable < 4 {
		t.Fatalf("REF-SRC-USQUE-2 scope rows %d want >= 4 non-portable", nonPortable)
	}
	if portable < 2 {
		t.Fatalf("REF-SRC-USQUE-3 portable rows %d want >= 2", portable)
	}
	t.Logf("REF-SRC-USQUE audit: %d rows (%d non-portable, %d portable); verdict=%q",
		len(ArchREFSRCUsqueAudit), nonPortable, portable, ArchREFSRCUsqueScopeVerdict())
}
