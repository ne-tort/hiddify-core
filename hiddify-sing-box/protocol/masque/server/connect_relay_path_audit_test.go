package server

import (
	_ "embed"
	"strings"
	"testing"
)

//go:embed connect_stream.go
var connectStreamRelayAuditSource string

// TestArchREF2ServerRelayPathParity (REF2-5): template handler uses relay.TCPForward entry.
func TestArchREF2ServerRelayPathParity(t *testing.T) {
	t.Parallel()
	src := struct {
		name, body, relayAnchor string
	}{
		"connect_stream.go", connectStreamRelayAuditSource, "relay.TCPForward",
	}
	if !strings.Contains(src.body, src.relayAnchor) {
		t.Fatalf("%s: missing relay anchor %q", src.name, src.relayAnchor)
	}
	if strings.Contains(src.body, "forwarder") {
		t.Fatalf("%s: CONNECT-stream must not use L3b forwarder", src.name)
	}
	idxDuplex := strings.Index(src.body, "EnableFullDuplex()")
	idxHeader := strings.Index(src.body, "WriteHeader(http.StatusOK)")
	idxRelay := strings.Index(src.body, src.relayAnchor)
	if idxDuplex < 0 || idxHeader < 0 || idxRelay < 0 {
		t.Fatalf("%s: missing full-duplex / WriteHeader / %s anchors", src.name, src.relayAnchor)
	}
	if idxDuplex > idxHeader || idxHeader > idxRelay {
		t.Fatalf("%s: wire order want EnableFullDuplex < WriteHeader < %s; got %d %d %d",
			src.name, src.relayAnchor, idxDuplex, idxHeader, idxRelay)
	}
	if !strings.Contains(src.body, "relay.TuneTCPOutbound") {
		t.Fatalf("%s: missing relay.TuneTCPOutbound", src.name)
	}
}
