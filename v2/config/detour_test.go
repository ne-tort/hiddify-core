package config_test

import (
	"testing"

	"github.com/hiddify/hiddify-core/v2/config"
	"github.com/sagernet/sing-box/option"
)

func dialerDetour(t *testing.T, opts any) string {
	t.Helper()
	w, ok := opts.(option.DialerOptionsWrapper)
	if !ok {
		t.Fatalf("options %T do not expose DialerOptions", opts)
	}
	return w.TakeDialerOptions().Detour
}

func TestBuildPreservesOutboundDetour(t *testing.T) {
	profile := `{
  "outbounds": [
    {
      "type": "shadowsocks",
      "tag": "relay §hide§",
      "server": "127.0.0.1",
      "server_port": 8388,
      "method": "aes-128-gcm",
      "password": "secret"
    },
    {
      "type": "shadowsocks",
      "tag": "main",
      "server": "127.0.0.1",
      "server_port": 8389,
      "method": "aes-128-gcm",
      "password": "secret",
      "detour": "relay §hide§"
    }
  ]
}`
	h := config.DefaultHiddifyOptions()
	built, err := config.BuildConfig(testCtx(), h, &config.ReadOptions{Content: profile})
	if err != nil {
		t.Fatal(err)
	}
	var mainDetour string
	foundRelay, foundMain := false, false
	for _, ob := range built.Outbounds {
		switch ob.Tag {
		case "relay §hide§":
			foundRelay = true
		case "main":
			foundMain = true
			mainDetour = dialerDetour(t, ob.Options)
		}
	}
	if !foundRelay || !foundMain {
		t.Fatalf("relay=%v main=%v", foundRelay, foundMain)
	}
	if mainDetour != "relay §hide§" {
		t.Fatalf("main detour=%q, want relay §hide§", mainDetour)
	}
}

func TestBuildRemapsLogicalDetour(t *testing.T) {
	profile := `{
  "outbounds": [
    {
      "type": "shadowsocks",
      "tag": "main",
      "server": "127.0.0.1",
      "server_port": 8389,
      "method": "aes-128-gcm",
      "password": "secret",
      "detour": "direct"
    }
  ]
}`
	h := config.DefaultHiddifyOptions()
	built, err := config.BuildConfig(testCtx(), h, &config.ReadOptions{Content: profile})
	if err != nil {
		t.Fatal(err)
	}
	for _, ob := range built.Outbounds {
		if ob.Tag != "main" {
			continue
		}
		got := dialerDetour(t, ob.Options)
		if got != config.OutboundDirectTag {
			t.Fatalf("detour=%q want %q", got, config.OutboundDirectTag)
		}
		return
	}
	t.Fatal("main outbound missing")
}

func TestRemapDialerDetour(t *testing.T) {
	if got := config.RemapDialerDetour(""); got != "" {
		t.Fatalf("empty → %q", got)
	}
	if got := config.RemapDialerDetour("direct"); got != config.OutboundDirectTag {
		t.Fatalf("direct → %q", got)
	}
	if got := config.RemapDialerDetour("relay"); got != "relay" {
		t.Fatalf("relay → %q", got)
	}
	if got := config.RemapDialerDetour("block"); got != "" {
		t.Fatalf("block → %q", got)
	}
}
