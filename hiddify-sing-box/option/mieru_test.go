package option

import (
	"testing"

	"github.com/sagernet/sing/common/json"
)

func TestMieruOutboundOptions_UnmarshalJSON_CompatFields(t *testing.T) {
	raw := []byte(`{
		"server": "31.57.158.219",
		"server_port": 0,
		"handshakeMode": "HANDSHAKE_NO_WAIT",
		"multiplexing": "MULTIPLEXING_HIGH",
		"username": "u",
		"password": "p",
		"portBindings": [
			{"protocol": "UDP", "port": 0, "portRange": "17795-17798"}
		]
	}`)
	var opts MieruOutboundOptions
	if err := json.Unmarshal(raw, &opts); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}
	if opts.HandshakeMode != "HANDSHAKE_NO_WAIT" {
		t.Fatalf("expected handshake mode from handshakeMode alias, got %q", opts.HandshakeMode)
	}
	if opts.Transport != "UDP" {
		t.Fatalf("expected transport inferred from portBindings protocol, got %q", opts.Transport)
	}
	if len(opts.ServerPortRanges) != 1 || opts.ServerPortRanges[0] != "17795-17798" {
		t.Fatalf("expected port range from portBindings, got %#v", opts.ServerPortRanges)
	}
}
