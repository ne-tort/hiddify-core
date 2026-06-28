package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func requireContractSubstrings(t *testing.T, src, label string, needles ...string) {
	t.Helper()
	for _, needle := range needles {
		if !strings.Contains(src, needle) {
			t.Fatalf("%s: missing %q", label, needle)
		}
	}
}

func readMasqueContractsDoc(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := wd
	for range 10 {
		path := filepath.Join(dir, "docs", "masque", "layers", "CLIENT-SERVER-CONTRACTS.md")
		if data, err := os.ReadFile(path); err == nil {
			return string(data)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("CLIENT-SERVER-CONTRACTS.md not found (run from hiddify-app checkout)")
	return ""
}
