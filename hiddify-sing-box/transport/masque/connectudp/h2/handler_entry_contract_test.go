package h2

import (
	_ "embed"
	"strings"
	"testing"
)

//go:embed handler_entry.go
var connectUDPH2HandlerEntrySource string

// TestConnectUDPH2HandlerWireContract locks H2 CONNECT-UDP RFC single-stream server wire order.
func TestConnectUDPH2HandlerWireContract(t *testing.T) {
	t.Parallel()
	for _, sub := range []string{
		`EnableFullDuplex()`,
		`CapsuleProtocolHeader`,
		`WriteHeader(http.StatusOK)`,
		`ServeH2(`,
		`tuneH2OnwardUDP`,
		`rejectLegacyAsymHeaders`,
	} {
		if !strings.Contains(connectUDPH2HandlerEntrySource, sub) {
			t.Fatalf("handler_entry.go: missing %q", sub)
		}
	}
	idxDuplex := strings.Index(connectUDPH2HandlerEntrySource, "EnableFullDuplex()")
	idxHeader := strings.Index(connectUDPH2HandlerEntrySource, "WriteHeader(http.StatusOK)")
	idxServe := strings.Index(connectUDPH2HandlerEntrySource, "ServeH2(")
	if idxDuplex < 0 || idxHeader < 0 || idxServe < 0 {
		t.Fatal("handler_entry.go: missing wire anchors")
	}
	if !(idxDuplex < idxHeader && idxHeader < idxServe) {
		t.Fatalf("wire order want EnableFullDuplex < WriteHeader < ServeH2; got duplex=%d header=%d serve=%d",
			idxDuplex, idxHeader, idxServe)
	}
	if strings.Contains(connectUDPH2HandlerEntrySource, "ServeH2FromRequest") ||
		strings.Contains(connectUDPH2HandlerEntrySource, "SessionRegistry") {
		t.Fatal("handler_entry.go: asym registry / ServeH2FromRequest must be gone")
	}
}
