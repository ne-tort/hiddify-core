package config

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEmptyProfileRoundTripAndWarpBuild(t *testing.T) {
	ctx := context.Background()
	hopts := DefaultHiddifyOptions()
	hopts.Warp.EnableMasque = true
	hopts.Warp.MasqueConfig = WarpMasqueConfig{
		PrivateKey: "dGVzdA==", PublicKey: "dGVzdA==", IPv4: "172.16.0.2",
		Server: "162.159.198.1", ServerPort: 443,
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "p.tmp.json")
	dst := filepath.Join(dir, "p.json")
	os.WriteFile(src, []byte(`{"outbounds":[]}`), 0644)

	parsed, err := ParseConfigBytes(ctx, &ReadOptions{Path: src}, true, hopts, false)
	if err != nil {
		t.Fatal(err)
	}
	if string(parsed) != `{"outbounds":[]}` {
		t.Fatalf("parsed=%q", parsed)
	}
	os.WriteFile(dst, parsed, 0644)
	os.WriteFile(ProfileSourcePath(dst), []byte(`{}`), 0644) // corrupted src

	built, err := ParseBuildConfigBytes(ctx, hopts, &ReadOptions{Path: ProfileSourcePath(dst)})
	if err != nil {
		t.Fatal("build from {} src:", err)
	}
	if !strings.Contains(string(built), "select") {
		t.Fatalf("missing select outbound in %s", built)
	}
	if strings.Contains(string(built), WarpMasqueTag) {
		t.Fatalf("WARP must not be mixed into empty profile build: %s", built)
	}

	// UTF-8 BOM must not break parse (Windows editors / PowerShell -Encoding utf8).
	bomPath := filepath.Join(dir, "bom.json")
	os.WriteFile(bomPath, append([]byte{0xEF, 0xBB, 0xBF}, []byte(`{"outbounds":[]}`)...), 0644)
	if _, err := ParseBuildConfigBytes(ctx, hopts, &ReadOptions{Path: bomPath}); err != nil {
		t.Fatal("BOM profile:", err)
	}
}
