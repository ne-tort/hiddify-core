package hcore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ne-tort/pathology-core/v2/config"
	"github.com/sagernet/sing-box/experimental/libbox"
)

func TestBuildConfigUsesJSONNotPoisonedSrc(t *testing.T) {
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "profile.json")
	srcPath := filepath.Join(dir, "profile.src")

	// Poisoned sidecar (historical empty-compile / Parse write).
	if err := os.WriteFile(srcPath, []byte(`{
  "log": {"level": "warn"},
  "outbounds": [
    {"type": "direct", "tag": "direct"},
    {"type": "block", "tag": "block"}
  ],
  "route": {"final": "direct"}
}`), 0o644); err != nil {
		t.Fatal(err)
	}
	vless := `{
  "outbounds": [
    {
      "type": "vless",
      "tag": "vless-leaf",
      "server": "1.2.3.4",
      "server_port": 443,
      "uuid": "00000000-0000-0000-0000-000000000001",
      "tls": { "enabled": true, "server_name": "example.com" }
    }
  ]
}`
	if err := os.WriteFile(jsonPath, []byte(vless), 0o644); err != nil {
		t.Fatal(err)
	}

	prev := static.ClientOptions
	static.ClientOptions = config.DefaultClientOptions()
	t.Cleanup(func() { static.ClientOptions = prev })

	ctx := libbox.BaseContext(nil)
	built, err := BuildConfig(ctx, &StartRequest{ConfigPath: jsonPath})
	if err != nil {
		t.Fatal(err)
	}
	var sawVless bool
	for _, ob := range built.Outbounds {
		if ob.Type == "vless" {
			sawVless = true
			break
		}
	}
	if !sawVless {
		t.Fatal("Start must build VLESS from .json, not Direct stub .src")
	}
}

func TestBuildConfigRefusesDroppedLeaves(t *testing.T) {
	raw := `{
  "outbounds": [
    {
      "type": "vless",
      "tag": "keep-me",
      "server": "1.2.3.4",
      "server_port": 443,
      "uuid": "00000000-0000-0000-0000-000000000001"
    },
    {
      "type": "vless",
      "tag": "drop-me-ipv6",
      "server": "2001:db8::1",
      "server_port": 443,
      "uuid": "00000000-0000-0000-0000-000000000002"
    }
  ]
}`
	prev := static.ClientOptions
	opt := config.DefaultClientOptions()
	opt.SubscriptionIPv6 = false
	static.ClientOptions = opt
	t.Cleanup(func() { static.ClientOptions = prev })

	ctx := libbox.BaseContext(nil)
	// Disable the keep-me leaf via DisabledOutboundTags so tags becomes empty while
	// input still had proxy leaves → must error, not select→direct.
	opt.DisabledOutboundTags = []string{"keep-me", "drop-me-ipv6"}
	_, err := config.BuildConfig(ctx, opt, &config.ReadOptions{Content: raw})
	if err == nil {
		t.Fatal("expected refusing Direct fallback when all proxy leaves disabled")
	}
	if !strings.Contains(err.Error(), "refusing Direct fallback") {
		t.Fatalf("want refusing Direct fallback, got %v", err)
	}
}
