package masque

import (
	"os"
	"slices"
	"testing"
)

func TestMasqueDocumentedEnvVarsExist(t *testing.T) {
	if len(MasqueDocumentedEnvVars) == 0 {
		return // prod dataplane fully zero-env
	}
	sorted := slices.Clone(MasqueDocumentedEnvVars)
	slices.Sort(sorted)
	if !slices.IsSorted(MasqueDocumentedEnvVars) {
		t.Fatalf("MasqueDocumentedEnvVars must stay sorted: got %v", MasqueDocumentedEnvVars)
	}
	for _, name := range MasqueDocumentedEnvVars {
		if name == "" {
			t.Fatal("empty env var name in registry")
		}
		if os.Getenv(name) != "" {
			t.Logf("note: %s is set in test environment", name)
		}
	}
}
