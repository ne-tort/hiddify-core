package http3

import (
	_ "embed"
	"strings"
	"testing"
)

//go:embed masque_wake.go
var http3MasqueWakeProdSource string

// TestHTTP3MasqueWakeNoM9ConnSend locks STR-STRUCT-30 / G10: http3 bidi wake must not call M9 conn send hooks.
func TestHTTP3MasqueWakeNoM9ConnSend(t *testing.T) {
	t.Parallel()
	for _, sym := range []string{"MasqueWakeConnSend", "MasqueWakeConnSendDatagramCoalesced"} {
		if strings.Contains(http3MasqueWakeProdSource, sym) {
			t.Fatalf("http3/masque_wake.go must not reference M9 hook %q", sym)
		}
	}
	if !strings.Contains(http3MasqueWakeProdSource, "QUICStream()") {
		t.Fatal("http3/masque_wake.go must route bidi wake through datagramStream.QUICStream()")
	}
}
