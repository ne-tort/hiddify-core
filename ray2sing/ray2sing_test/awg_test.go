package ray2sing_test

import (
	"testing"

	"github.com/hiddify/ray2sing/ray2sing"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/libbox"
	T "github.com/sagernet/sing-box/option"
)

// Sample keys (32-byte WireGuard keys, base64); values match json_editor examples.
const (
	testPrivateKey = "YNXtAzepDqRv9H52osJVDQnznT5AM11eCK3ESpwSt04="
	testPublicKey  = "Z1XXLsKYkYxuiYjJIkRvtIKFepCYHTgON+GwPq7SOV4="
)

func parseSingboxOptions(t *testing.T, raw string) T.Options {
	t.Helper()
	ctx := libbox.BaseContext(nil)
	j, err := ray2sing.Ray2Singbox(ctx, raw, false)
	if err != nil {
		t.Fatalf("Ray2Singbox: %v", err)
	}
	var opt T.Options
	if err := opt.UnmarshalJSONContext(ctx, j); err != nil {
		t.Fatalf("UnmarshalJSONContext: %v\n%s", err, string(j))
	}
	return opt
}

func TestAwgSingbox_WgURL_NoObfuscation_WireGuardEndpoint(t *testing.T) {
	raw := "wg://198.51.100.10:51820/?pk=" + testPrivateKey + "&address=10.0.0.2/24&publickey=" + testPublicKey
	opt := parseSingboxOptions(t, raw)
	if len(opt.Endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(opt.Endpoints))
	}
	ep := opt.Endpoints[0]
	if ep.Type != C.TypeWireGuard {
		t.Fatalf("endpoint type: got %q want %q", ep.Type, C.TypeWireGuard)
	}
	if ep.Tag != "WG § 0" {
		t.Errorf("tag: got %q", ep.Tag)
	}
	wg, ok := ep.Options.(*T.WireGuardEndpointOptions)
	if !ok {
		t.Fatalf("options type %T", ep.Options)
	}
	if wg.PrivateKey != testPrivateKey {
		t.Errorf("private_key mismatch")
	}
	if len(wg.Peers) != 1 {
		t.Fatalf("peers: %d", len(wg.Peers))
	}
	if wg.Peers[0].Address != "198.51.100.10" || wg.Peers[0].Port != 51820 {
		t.Errorf("peer endpoint: %#v", wg.Peers[0])
	}
	if wg.Peers[0].PublicKey != testPublicKey {
		t.Errorf("peer public_key")
	}
}

func TestAwgSingbox_WireguardScheme_SameAsWg(t *testing.T) {
	q := "pk=" + testPrivateKey + "&address=10.0.0.2/24&publickey=" + testPublicKey
	optWg := parseSingboxOptions(t, "wg://198.51.100.10:51820/?"+q)
	optWireguard := parseSingboxOptions(t, "wireguard://198.51.100.10:51820/?"+q)
	if optWg.Endpoints[0].Type != optWireguard.Endpoints[0].Type {
		t.Fatalf("type wg=%q wireguard=%q", optWg.Endpoints[0].Type, optWireguard.Endpoints[0].Type)
	}
}

func TestAwgSingbox_AwgURL_WithObfuscation_AwgEndpoint(t *testing.T) {
	raw := "awg://198.51.100.10:51820/?pk=" + testPrivateKey + "&address=10.0.0.2/24&publickey=" + testPublicKey +
		"&jc=4&jmin=10&jmax=50"
	opt := parseSingboxOptions(t, raw)
	if len(opt.Endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(opt.Endpoints))
	}
	ep := opt.Endpoints[0]
	if ep.Type != C.TypeAwg {
		t.Fatalf("endpoint type: got %q want %q", ep.Type, C.TypeAwg)
	}
	awg, ok := ep.Options.(*T.AwgEndpointOptions)
	if !ok {
		t.Fatalf("options type %T", ep.Options)
	}
	if awg.Jc != 4 || awg.Jmin != 10 || awg.Jmax != 50 {
		t.Errorf("jc/jmin/jmax: %#v", awg)
	}
	if len(awg.Peers) != 1 || awg.Peers[0].PublicKey != testPublicKey {
		t.Errorf("peers: %#v", awg.Peers)
	}
}

func TestAwgSingbox_WgURL_WithObfuscation_AwgEndpoint(t *testing.T) {
	raw := "wg://198.51.100.10:51820/?pk=" + testPrivateKey + "&address=10.0.0.2/24&publickey=" + testPublicKey +
		"&jc=4&jmin=10&jmax=50"
	opt := parseSingboxOptions(t, raw)
	if opt.Endpoints[0].Type != C.TypeAwg {
		t.Fatalf("expected awg when obfuscation params present, got %q", opt.Endpoints[0].Type)
	}
}

func TestAwgSingbox_INI_NoObfuscation_WireGuardEndpoint(t *testing.T) {
	raw := `[Interface]
PrivateKey = ` + testPrivateKey + `
Address = 10.0.0.2/32

[Peer]
PublicKey = ` + testPublicKey + `
AllowedIPs = 0.0.0.0/0
Endpoint = 198.51.100.10:51820
`
	opt := parseSingboxOptions(t, raw)
	if len(opt.Endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(opt.Endpoints))
	}
	if opt.Endpoints[0].Type != C.TypeWireGuard {
		t.Fatalf("type %q", opt.Endpoints[0].Type)
	}
	if opt.Endpoints[0].Tag != "wireguard § 0" {
		t.Errorf("tag %q", opt.Endpoints[0].Tag)
	}
}

func TestAwgSingbox_INI_WithObfuscation_AwgEndpoint(t *testing.T) {
	raw := `[Interface]
PrivateKey = ` + testPrivateKey + `
Address = 10.0.0.2/32
Jc = 4
Jmin = 10
Jmax = 50

[Peer]
PublicKey = ` + testPublicKey + `
AllowedIPs = 0.0.0.0/0
Endpoint = 198.51.100.10:51820
`
	opt := parseSingboxOptions(t, raw)
	if len(opt.Endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(opt.Endpoints))
	}
	if opt.Endpoints[0].Type != C.TypeAwg {
		t.Fatalf("type %q", opt.Endpoints[0].Type)
	}
	if opt.Endpoints[0].Tag != "awg § 0" {
		t.Errorf("tag %q", opt.Endpoints[0].Tag)
	}
}
