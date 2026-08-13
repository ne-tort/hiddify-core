package config_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ne-tort/pathology-core/v2/config"
	"github.com/sagernet/sing-box/experimental/libbox"
	_ "github.com/sagernet/sing-box/include"
)

func softParseCtx() context.Context {
	return libbox.BaseContext(nil)
}

func TestSoftParseSkipsInvalidRealityKeepsPlainVless(t *testing.T) {
	raw := `{
  "outbounds": [
    {
      "type": "vless",
      "tag": "plain",
      "server": "31.58.171.145",
      "server_port": 28028,
      "uuid": "387c6b84-2e30-4b67-83c9-aa5692550e65"
    },
    {
      "type": "vless",
      "tag": "reality-bad",
      "server": "31.58.171.145",
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
	parsed, err := config.ParseConfigBytes(softParseCtx(), &config.ReadOptions{Content: raw}, true, config.DefaultClientOptions(), false)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	s := string(parsed)
	if !strings.Contains(s, `"tag":"plain"`) && !strings.Contains(s, `"tag": "plain"`) {
		t.Fatalf("expected plain outbound, got %s", s)
	}
	if strings.Contains(s, "reality-bad") {
		t.Fatalf("invalid reality outbound must be dropped: %s", s)
	}
}

func TestSoftParseSkipsUnknownOutboundType(t *testing.T) {
	raw := `{
  "outbounds": [
    {"type": "vless", "tag": "ok", "server": "1.2.3.4", "server_port": 443, "uuid": "387c6b84-2e30-4b67-83c9-aa5692550e65"},
    {"type": "not-a-real-protocol", "tag": "bad", "server": "1.2.3.4"}
  ]
}`
	parsed, err := config.ParseConfigBytes(softParseCtx(), &config.ReadOptions{Content: raw}, true, config.DefaultClientOptions(), false)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	s := string(parsed)
	if !strings.Contains(s, `"tag":"ok"`) && !strings.Contains(s, `"tag": "ok"`) {
		t.Fatalf("expected ok outbound, got %s", s)
	}
	if strings.Contains(s, "not-a-real-protocol") || strings.Contains(s, `"bad"`) {
		t.Fatalf("unknown type must be dropped: %s", s)
	}
}

func TestSoftParseKeepsWireGuardEndpointWithPathology(t *testing.T) {
	raw := `{
  "endpoints": [{
    "address": ["10.8.10.2", "fd10:8:a::2"],
    "mtu": 1280,
    "pathology": {"auto": true, "enabled": true, "key": "b+MgrlV9JJMQLK7U0xBDgWxPB6DX3Wvijt6Ueo1rIaI="},
    "peers": [{
      "address": "31.58.171.145",
      "persistent_keepalive_interval": 25,
      "port": 47684,
      "public_key": "6KTid8OUZl2hoVmFKp48bAwnr5UImjLMRf6EajCENUI="
    }],
    "private_key": "cIPq1kWIIPewXHtEWmuyQKFTFmQwv8D5iH6g+K7b1Ec=",
    "subnet": "10.8.10.0/24",
    "subnet6": "fd10:8:a::/64",
    "tag": "cp-wg-seed-pathology-auto-client",
    "type": "wireguard",
    "use_exit_node": true
  }],
  "outbounds": [{
    "type": "vless",
    "tag": "plain",
    "server": "31.58.171.145",
    "server_port": 28028,
    "uuid": "387c6b84-2e30-4b67-83c9-aa5692550e65"
  }]
}`
	parsed, err := config.ParseConfigBytes(softParseCtx(), &config.ReadOptions{Content: raw}, true, config.DefaultClientOptions(), false)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	s := string(parsed)
	if !strings.Contains(s, "cp-wg-seed-pathology-auto-client") {
		t.Fatalf("missing wg endpoint: %s", s)
	}
	if !strings.Contains(s, "plain") {
		t.Fatalf("missing plain outbound: %s", s)
	}

	var root map[string]any
	if err := json.Unmarshal(parsed, &root); err != nil {
		t.Fatal(err)
	}
	eps, _ := root["endpoints"].([]any)
	if len(eps) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(eps))
	}
}

func TestSoftParseCpSubscriptionMixedReality(t *testing.T) {
	// Reality rows without public_key (agent bug) must not drop WG/plain rows.
	raw := `{
  "endpoints": [{
    "type": "wireguard",
    "tag": "wg1",
    "private_key": "cIPq1kWIIPewXHtEWmuyQKFTFmQwv8D5iH6g+K7b1Ec=",
    "subnet": "10.8.10.0/24",
    "address": ["10.8.10.2"],
    "peers": [{"address": "31.58.171.145", "port": 47684, "public_key": "6KTid8OUZl2hoVmFKp48bAwnr5UImjLMRf6EajCENUI="}]
  }],
  "outbounds": [
    {"type": "vless", "tag": "plain", "server": "31.58.171.145", "server_port": 28028, "uuid": "387c6b84-2e30-4b67-83c9-aa5692550e65"},
    {"type": "vless", "tag": "reality", "server": "31.58.171.145", "server_port": 443, "uuid": "387c6b84-2e30-4b67-83c9-aa5692550e65", "tls": {"enabled": true, "reality": {"enabled": true, "short_id": "ab"}, "server_name": "x", "utls": {"enabled": true, "fingerprint": "chrome"}}}
  ]
}`
	parsed, err := config.ParseConfigBytes(softParseCtx(), &config.ReadOptions{Content: raw}, true, config.DefaultClientOptions(), false)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	s := string(parsed)
	if !strings.Contains(s, "wg1") || !strings.Contains(s, "plain") {
		t.Fatalf("expected wg + plain, got %s", s)
	}
	if strings.Contains(s, `"tag":"reality"`) || strings.Contains(s, `"tag": "reality"`) {
		t.Fatalf("invalid reality must be dropped: %s", s)
	}
}
