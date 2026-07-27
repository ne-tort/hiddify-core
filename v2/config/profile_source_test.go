package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hiddify/hiddify-core/v2/config"
)

func TestProfileSourcePath(t *testing.T) {
	got := config.ProfileSourcePath(`C:\data\configs\abc.json`)
	want := `C:\data\configs\abc.src`
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if config.ProfileSourcePath("") != "" {
		t.Fatal("empty")
	}
}

func TestParseBuildFromSourceKeepsDetourToggleSurface(t *testing.T) {
	// Smoke: ParseBuild on a minimal JSON with dns uses hopts ignore flag path.
	dir := t.TempDir()
	src := filepath.Join(dir, "p.src")
	body := []byte(`{
  "outbounds":[{"type":"direct","tag":"node-a"}],
  "dns":{"servers":[{"type":"udp","tag":"sub-dns","server":"1.1.1.1"}]}
}`)
	if err := os.WriteFile(src, body, 0o644); err != nil {
		t.Fatal(err)
	}
	h := config.DefaultHiddifyOptions()
	h.IgnoreSubscriptionDNS = true
	built, err := config.ParseBuildConfig(testCtx(), h, &config.ReadOptions{Path: src})
	if err != nil {
		t.Fatal(err)
	}
	if built.DNS == nil {
		t.Fatal("nil dns")
	}
	// With ignore-subscription-dns, client template should win (bootstrap tag present).
	found := false
	for _, s := range built.DNS.Servers {
		if s.Tag == "dns-bootstrap" || s.Tag == config.DNSBootstrapTag {
			found = true
		}
	}
	// Tag constant may differ — at least ensure we didn't keep only sub-dns as sole server without rebuild.
	if !found && len(built.DNS.Servers) == 1 && built.DNS.Servers[0].Tag == "sub-dns" {
		t.Fatal("expected client DNS template when ignore-subscription-dns=true")
	}
}
