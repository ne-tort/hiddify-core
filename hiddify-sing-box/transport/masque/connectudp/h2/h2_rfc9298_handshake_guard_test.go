package h2

import (
	_ "embed"
	"strings"
	"testing"
)

//go:embed dial.go
var h2DialProdSource string

// TestConnectUDPH2DialRFC9298Handshake locks UDP-13 / G9: prod Extended CONNECT uses RFC 9298 fields.
func TestConnectUDPH2DialRFC9298Handshake(t *testing.T) {
	t.Parallel()
	checks := []struct {
		needle string
		msg    string
	}{
		{`http.MethodConnect`, "dial must use CONNECT method"},
		{`req.Header.Set(":protocol", ConnectProto)`, "dial must set :protocol connect-udp"},
		{`http3.CapsuleProtocolHeader`, "dial must set Capsule-Protocol"},
		{`h2c.CapsuleProtocolHeaderValue()`, "dial must use RFC 9297 Capsule-Protocol structured field"},
		{`req.ContentLength = -1`, "dial must keep Extended CONNECT upload body open (ContentLength -1)"},
		{`httpx.NewH2ExtendedConnectRequestContext`, "dial must use H2 Extended CONNECT request context"},
	}
	for _, c := range checks {
		if !strings.Contains(h2DialProdSource, c.needle) {
			t.Fatalf("dial.go: %s (missing %q)", c.msg, c.needle)
		}
	}
	if ConnectProto != "connect-udp" {
		t.Fatalf("ConnectProto=%q want connect-udp", ConnectProto)
	}
}
