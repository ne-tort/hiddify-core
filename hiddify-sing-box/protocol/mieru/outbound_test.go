package mieru

import (
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestBuildMieruClientConfig_AppliesHandshakeMode(t *testing.T) {
	opts := option.MieruOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     "1.1.1.1",
			ServerPort: 17795,
		},
		Transport:     "UDP",
		UserName:      "u",
		Password:      "p",
		HandshakeMode: "HANDSHAKE_NO_WAIT",
	}
	cfg, err := buildMieruClientConfig(opts, mieruDialer{})
	if err != nil {
		t.Fatalf("unexpected build error: %v", err)
	}
	if got := cfg.Profile.GetHandshakeMode().String(); got != "HANDSHAKE_NO_WAIT" {
		t.Fatalf("unexpected handshake mode in profile: %s", got)
	}
}

func TestValidateMieruOptions_RejectsInvalidHandshakeMode(t *testing.T) {
	opts := option.MieruOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     "1.1.1.1",
			ServerPort: 17795,
		},
		Transport:     "UDP",
		UserName:      "u",
		Password:      "p",
		HandshakeMode: "HANDSHAKE_BROKEN",
	}
	if err := validateMieruOptions(opts); err == nil {
		t.Fatal("expected validation error for invalid handshake mode")
	}
}
