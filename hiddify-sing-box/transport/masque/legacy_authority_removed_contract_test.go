package masque

import (
	"os"
	"path/filepath"
	"testing"
)

func singBoxRootFromMasque(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for range 8 {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			if _, err := os.Stat(filepath.Join(dir, "transport", "masque")); err == nil {
				return dir
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("hiddify-sing-box root not found")
	return ""
}

func mustNotExistUnder(t *testing.T, root, rel string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if _, err := os.Stat(path); err == nil {
		t.Fatalf("legacy path must stay removed: %s", rel)
	} else if !os.IsNotExist(err) {
		t.Fatalf("stat %s: %v", rel, err)
	}
}

func mustNotMatchGlob(t *testing.T, root, globPattern string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(root, filepath.FromSlash(globPattern)))
	if err != nil {
		t.Fatalf("glob %s: %v", globPattern, err)
	}
	for _, m := range matches {
		rel, err := filepath.Rel(root, m)
		if err != nil {
			t.Fatalf("rel %s: %v", m, err)
		}
		t.Fatalf("legacy glob match must stay removed: %s", filepath.ToSlash(rel))
	}
}

// TestLegacyAuthorityPathsRemoved locks LEGACY cleanup: connect_authority / masquethin orphans must not return.
func TestLegacyAuthorityPathsRemoved(t *testing.T) {
	t.Parallel()
	root := singBoxRootFromMasque(t)

	for _, rel := range []string{
		"cmd/masque-thin-client",
		"cmd/masque-thin-server",
		"internal/masquethin",
	} {
		mustNotExistUnder(t, root, rel)
	}

	mustNotMatchGlob(t, root, "transport/masque/h3/authority_*.go")
	mustNotMatchGlob(t, root, "protocol/masque/server/connect_authority_*.go")

	// Guard against reintroducing authority_listen_bridge in masque root.
	bridge := filepath.Join(root, "transport", "masque", "authority_listen_bridge.go")
	if _, err := os.Stat(bridge); err == nil {
		t.Fatal("authority_listen_bridge.go must stay removed")
	} else if !os.IsNotExist(err) {
		t.Fatalf("stat authority_listen_bridge.go: %v", err)
	}
}
