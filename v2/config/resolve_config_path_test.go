package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveConfigReadPathUsesJSON(t *testing.T) {
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "p.json")
	srcPath := filepath.Join(dir, "p.src")
	if err := os.WriteFile(jsonPath, []byte(`{"outbounds":[{"type":"vless","tag":"v"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// Poisoned Direct stub sidecar must NOT win over the profile pool.
	if err := os.WriteFile(srcPath, []byte(`{"outbounds":[{"type":"direct","tag":"direct"},{"type":"block","tag":"block"}],"route":{"final":"direct"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	got := ResolveConfigReadPath(jsonPath)
	if got != jsonPath {
		t.Fatalf("got %q want json %q (must ignore Direct stub .src)", got, jsonPath)
	}
}

func TestResolveConfigReadPathEmpty(t *testing.T) {
	if ResolveConfigReadPath("") != "" {
		t.Fatal("empty path should stay empty")
	}
}
