package h2

import (
	_ "embed"
	"strings"
	"testing"
)

//go:embed handler_entry.go
var connectUDPH2HandlerEntrySource string

// TestConnectUDPH2HandlerWireContract locks H2 CONNECT-UDP server wire order (moved from protocol handler).
func TestConnectUDPH2HandlerWireContract(t *testing.T) {
	t.Parallel()
	for _, sub := range []string{
		`EnableFullDuplex()`,
		`CapsuleProtocolHeader`,
		`WriteHeader(http.StatusOK)`,
		`ServeH2FromRequest`,
		`tuneH2OnwardUDP`,
	} {
		if !strings.Contains(connectUDPH2HandlerEntrySource, sub) {
			t.Fatalf("handler_entry.go: missing %q", sub)
		}
	}
	idxDuplex := strings.Index(connectUDPH2HandlerEntrySource, "EnableFullDuplex()")
	idxHeader := strings.Index(connectUDPH2HandlerEntrySource, "WriteHeader(http.StatusOK)")
	idxRelay := strings.Index(connectUDPH2HandlerEntrySource, "ServeH2FromRequest")
	if idxDuplex < 0 || idxHeader < 0 || idxRelay < 0 {
		t.Fatal("handler_entry.go: missing full-duplex / WriteHeader / H2 relay ordering anchors")
	}
	if idxDuplex > idxHeader || idxHeader > idxRelay {
		t.Fatalf("wire order want EnableFullDuplex < WriteHeader < ServeH2FromRequest; got %d %d %d",
			idxDuplex, idxHeader, idxRelay)
	}
}
