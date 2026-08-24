package config_test

import (
	"strings"
	"testing"

	"github.com/ne-tort/pathology-core/v2/config"
)

func TestSoftParseKeepsDirectOutbound(t *testing.T) {
	raw := `{
  "outbounds": [
    {"type": "direct", "tag": "direct"},
    {"type": "vless", "tag": "plain", "server": "1.2.3.4", "server_port": 443, "uuid": "387c6b84-2e30-4b67-83c9-aa5692550e65"}
  ]
}`
	parsed, err := config.ParseConfigBytes(softParseCtx(), &config.ReadOptions{Content: raw}, true, config.DefaultClientOptions(), false)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	s := string(parsed)
	if !strings.Contains(s, `"tag":"direct"`) && !strings.Contains(s, `"tag": "direct"`) {
		t.Fatalf("direct outbound must be kept (no duplicate-tag false negative): %s", s)
	}
	if !strings.Contains(s, "plain") {
		t.Fatalf("plain outbound missing: %s", s)
	}
}

func TestSoftParseAllDroppedReturnsError(t *testing.T) {
	// Reality without public_key is invalid — soft filter drops it. With no other
	// protocol leaves left, filter must error (not return {"outbounds":[]}).
	raw := `{
  "outbounds": [
    {
      "type": "vless",
      "tag": "reality-bad",
      "server": "1.2.3.4",
      "server_port": 443,
      "uuid": "387c6b84-2e30-4b67-83c9-aa5692550e65",
      "tls": {
        "enabled": true,
        "reality": {"enabled": true, "short_id": "fcce710b121881d3"},
        "server_name": "www.example.com",
        "utls": {"enabled": true, "fingerprint": "chrome"}
      }
    }
  ]
}`
	_, err := config.ParseConfigBytes(softParseCtx(), &config.ReadOptions{Content: raw}, true, config.DefaultClientOptions(), false)
	if err == nil {
		t.Fatal("expected error when soft parse drops all protocol leaves")
	}
	if !strings.Contains(err.Error(), "dropped all") {
		t.Fatalf("unexpected error: %v", err)
	}
}
