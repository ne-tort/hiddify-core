package ray2sing

import (
	"testing"

	T "github.com/sagernet/sing-box/option"
)

func TestMieruSingbox_HandshakeModeAliases(t *testing.T) {
	tests := []string{
		"mieru://u:p@31.57.158.219?port=17795&protocol=UDP&handshake-mode=HANDSHAKE_NO_WAIT",
		"mieru://u:p@31.57.158.219?port=17795&protocol=UDP&handshake_mode=HANDSHAKE_NO_WAIT",
		"mieru://u:p@31.57.158.219?port=17795&protocol=UDP&handshakeMode=HANDSHAKE_NO_WAIT",
	}
	for _, uri := range tests {
		out, err := MieruSingbox(uri)
		if err != nil {
			t.Fatalf("unexpected error for uri %q: %v", uri, err)
		}
		opts, ok := out.Options.(*T.MieruOutboundOptions)
		if !ok {
			t.Fatalf("unexpected outbound options type: %T", out.Options)
		}
		if opts.HandshakeMode != "HANDSHAKE_NO_WAIT" {
			t.Fatalf("expected handshake mode to be parsed, got %q for uri %q", opts.HandshakeMode, uri)
		}
	}
}
