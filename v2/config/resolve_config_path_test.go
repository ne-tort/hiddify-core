package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveConfigReadPathPrefersSrc(t *testing.T) {
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "p.json")
	srcPath := filepath.Join(dir, "p.src")
	if err := os.WriteFile(jsonPath, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(srcPath, []byte("vless://x"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := ResolveConfigReadPath(jsonPath)
	if got != srcPath {
		t.Fatalf("got %q want %q", got, srcPath)
	}
}

func TestResolveConfigReadPathFallsBackToJSON(t *testing.T) {
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "p.json")
	if err := os.WriteFile(jsonPath, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	got := ResolveConfigReadPath(jsonPath)
	if got != jsonPath {
		t.Fatalf("got %q want %q", got, jsonPath)
	}
}
