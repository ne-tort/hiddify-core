package hcore

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ne-tort/pathology-core/v2/config"
	"github.com/sagernet/sing-box/experimental/libbox"
)

func TestBuildConfigFallsBackFromEmptySrcToJSON(t *testing.T) {
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "profile.json")
	srcPath := filepath.Join(dir, "profile.src")

	// .src: no proxy leaves (Direct-only) — historically preferred by Start.
	if err := os.WriteFile(srcPath, []byte(`{"outbounds":[{"type":"direct","tag":"direct"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// .json: real VLESS leaf that soft-parse keeps (matches UI / ping).
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
	built, err := buildConfigFromProfilePath(ctx, jsonPath, "")
	if err != nil {
		t.Fatal(err)
	}
	n := countBuiltProxyLeaves(built)
	if n < 1 {
		t.Fatalf("expected proxy leaves from .json fallback, got %d", n)
	}
}
