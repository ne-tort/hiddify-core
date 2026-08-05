package config

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func TestResolvedChainDetoursPrefersMap(t *testing.T) {
	c := ChainOptions{
		DetourTarget:  "old-exit",
		DetourMembers: []string{"a"},
		Detours:       map[string]string{"node1": "exit1", "node2": "balance"},
	}
	got := resolvedChainDetours(c)
	if got["node1"] != "exit1" || got["node2"] != "balance" {
		t.Fatalf("got=%v", got)
	}
	if _, ok := got["a"]; ok {
		t.Fatal("legacy should be ignored when map present")
	}
}

func TestResolvedChainDetoursLegacyExpand(t *testing.T) {
	c := ChainOptions{
		DetourTarget:  "exit",
		DetourMembers: []string{"a", "exit", "  b  ", ""},
	}
	got := resolvedChainDetours(c)
	if len(got) != 2 || got["a"] != "exit" || got["b"] != "exit" {
		t.Fatalf("got=%v", got)
	}
}

func TestChainExitForMissingAndSelf(t *testing.T) {
	detours := map[string]string{
		"a": "missing-exit",
		"b": "b",
		"c": "balance",
	}
	known := map[string]struct{}{
		"balance": {},
		"c":       {},
	}
	if chainExitFor("a", detours, known) != "" {
		t.Fatal("missing exit must skip")
	}
	if chainExitFor("b", detours, known) != "" {
		t.Fatal("self exit must skip")
	}
	if chainExitFor("c", detours, known) != "balance" {
		t.Fatal("balance exit should apply")
	}
}

func TestApplyDetourAllowsWarpMember(t *testing.T) {
	out := option.Outbound{
		Type: C.TypeVLESS,
		Tag:  WarpWGTag,
		Options: &option.VLESSOutboundOptions{
			DialerOptions: option.DialerOptions{},
		},
	}
	out = applyDetourToOutbound(out, "balance")
	opts := out.Options.(*option.VLESSOutboundOptions)
	if opts.Detour != "balance" {
		t.Fatalf("WARP-tagged member detour=%q want balance", opts.Detour)
	}
}

func TestBuildConfigChainDetoursMap(t *testing.T) {
	profile := `{
  "outbounds": [
    {"type":"vless","tag":"leaf-a","server":"1.1.1.1","server_port":443,"uuid":"00000000-0000-0000-0000-000000000001"},
    {"type":"vless","tag":"leaf-b","server":"1.1.1.2","server_port":443,"uuid":"00000000-0000-0000-0000-000000000002"}
  ]
}`
	h := DefaultHiddifyOptions()
	h.IgnoreSubscriptionRoute = true
	h.Chain = ChainOptions{
		Detours: map[string]string{
			"leaf-a": "balance",
			"leaf-b": "gone",
		},
	}
	built, err := BuildConfig(testCtx(), h, &ReadOptions{Content: profile})
	if err != nil {
		t.Fatal(err)
	}
	var gotA, gotB string
	for _, out := range built.Outbounds {
		opts, ok := out.Options.(*option.VLESSOutboundOptions)
		if !ok {
			continue
		}
		if out.Tag == "leaf-a" {
			gotA = opts.Detour
		}
		if out.Tag == "leaf-b" {
			gotB = opts.Detour
		}
	}
	if gotA != "balance" {
		t.Fatalf("leaf-a detour=%q", gotA)
	}
	if gotB != "" {
		t.Fatalf("leaf-b missing exit must be skipped, got %q", gotB)
	}
}
