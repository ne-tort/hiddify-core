package masque

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func h3ProdSource(t *testing.T, name string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	path := filepath.Clean(filepath.Join(filepath.Dir(file), "h3", name))
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read h3/%s: %v", name, err)
	}
	return string(b)
}

var m9ConnWakeForbiddenInMS3 = []string{
	"MasqueWakeConnSend",
	"MasqueWakeConnSendDatagramCoalesced",
	"SendDatagramNoWake",
}

// TestSTR05ProdBidiWakeUsesMS3NotM9 locks G5 / STR-05: CONNECT-stream wake uses quic MS3 hooks, not M9 datagram conn wake.
func TestSTR05ProdBidiWakeUsesMS3NotM9(t *testing.T) {
	t.Parallel()
	src := h3ProdSource(t, "bidi_wake.go")
	for _, sym := range m9ConnWakeForbiddenInMS3 {
		if strings.Contains(src, sym) {
			t.Fatalf("bidi_wake.go must not reference M9 datagram hook %q", sym)
		}
	}
	for _, needle := range []string{
		"quic.MasqueWakeBidiDuplex",
		"quic.MasqueWakeStreamSend",
		"c.h3.QUICStream()",
	} {
		if !strings.Contains(src, needle) {
			t.Fatalf("bidi_wake.go must route duplex wake via %q", needle)
		}
	}
}

// TestSTR05ProdDuplexCoordLegacyCut locks STR-MS3: legacy duplex_coord queue stays removed from prod.
func TestSTR05ProdDuplexCoordLegacyCut(t *testing.T) {
	t.Parallel()
	src := h3ProdSource(t, "duplex_coord.go")
	for _, forbidden := range []string{
		"BidiDuplexCoordEnabled",
		"maybeEnableDuplexFairDefer",
	} {
		if strings.Contains(src, forbidden) {
			t.Fatalf("duplex_coord.go must not retain legacy %q", forbidden)
		}
	}
}

// TestSTR05ProdDuplexFCGrantHooks locks saturated duplex download credit gating (MS3 fairness hooks).
func TestSTR05ProdDuplexFCGrantHooks(t *testing.T) {
	t.Parallel()
	bidi := h3ProdSource(t, "bidi_wake.go")
	for _, needle := range []string{
		"MasqueDuplexGrantPeerDownloadCredit",
		"MasqueUploadSendStarved",
		"MasqueRepromoteDuplexUploadSend",
	} {
		if !strings.Contains(bidi, needle) {
			t.Fatalf("bidi_wake.go must consult duplex FC hook %q", needle)
		}
	}
	duplex := h3ProdSource(t, "duplex_coord.go")
	if !strings.Contains(duplex, "MasqueSetBidiDuplexUploadStarted") {
		t.Fatal("duplex_coord.go must arm quic duplex upload-started flags")
	}
}

// TestSTR05ProdTunnelConnDownloadArmsDuplexWake locks RFC 9114 bidi: download drain path triggers MS3 delivery wake.
func TestSTR05ProdTunnelConnDownloadArmsDuplexWake(t *testing.T) {
	t.Parallel()
	src := h3ProdSource(t, "tunnel_conn.go")
	idx := strings.Index(src, "func (c *TunnelConn) writeH3DownloadToThin")
	if idx < 0 {
		t.Fatal("tunnel_conn.go missing writeH3DownloadToThin")
	}
	download := src[idx:]
	for _, needle := range []string{
		"beginDuplexDownload",
		"noteDownloadDeliveryWake",
	} {
		if !strings.Contains(download, needle) {
			t.Fatalf("H3 download drain must integrate duplex wake via %q", needle)
		}
	}
	if !strings.Contains(src, "wakeBidiSendAfterUpload") {
		t.Fatal("tunnel_conn.go must wake upload during saturated duplex")
	}
}
