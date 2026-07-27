package ray2sing

import (
	"strings"
	"testing"

	T "github.com/sagernet/sing-box/option"
)

func TestNormalizeDetourChain(t *testing.T) {
	in := "vless://a#exit&&detour=tuic://b#entry"
	got := normalizeDetourChain(in)
	want := "vless://a#exit -> tuic://b#entry"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if normalizeDetourChain("a -> b") != "a -> b" {
		t.Fatal("existing arrow must stay")
	}
}

func TestGetDialerOptionsReadsDetourTag(t *testing.T) {
	d := getDialerOptions(map[string]string{"detour": "relay"})
	if d.Detour != "relay" {
		t.Fatalf("got %q", d.Detour)
	}
	d = getDialerOptions(map[string]string{"detour": "tuic://host"})
	if d.Detour != "" {
		t.Fatalf("URL detour must not go into DialerOptions, got %q", d.Detour)
	}
}

func TestResolveDetourTagRefs(t *testing.T) {
	type ssOpts struct {
		T.DialerOptions
	}
	relay := T.Outbound{Type: "shadowsocks", Tag: "relay § 0", Options: &ssOpts{}}
	main := T.Outbound{Type: "shadowsocks", Tag: "main § 1", Options: &ssOpts{
		DialerOptions: T.DialerOptions{Detour: "relay"},
	}}
	outs := []T.Outbound{relay, main}
	resolveDetourTagRefs(outs, nil)
	got := outs[1].Options.(*ssOpts).Detour
	if got != "relay § 0" {
		t.Fatalf("resolved detour=%q", got)
	}
}

func TestGenerateConfigLiteAndDetourURL(t *testing.T) {
	// Minimal socks links — always available parsers.
	input := "socks://user:pass@127.0.0.1:1080#exit&&detour=socks://user:pass@127.0.0.1:1081#entry"
	opts, err := GenerateConfigLite(input, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(opts.Outbounds) < 2 {
		t.Fatalf("outbounds=%d", len(opts.Outbounds))
	}
	var exitDetour string
	var tags []string
	for _, ob := range opts.Outbounds {
		tags = append(tags, ob.Tag)
		if strings.HasPrefix(outboundTagBase(ob.Tag), "exit") {
			if w, ok := ob.Options.(T.DialerOptionsWrapper); ok {
				exitDetour = w.TakeDialerOptions().Detour
			}
		}
	}
	if exitDetour == "" {
		t.Fatalf("exit has empty detour; tags=%v", tags)
	}
	if outboundTagBase(exitDetour) != "entry" {
		t.Fatalf("exit detour=%q tags=%v", exitDetour, tags)
	}
}
