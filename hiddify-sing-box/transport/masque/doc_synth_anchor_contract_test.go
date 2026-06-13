package masque

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// requiredSynthAnchorFiles are real in-repo synth anchors referenced by MASQUE docs.
var requiredSynthAnchorFiles = []string{
	"connect_stream_ceiling_test.go",
	"connect_stream_bypass_matrix_test.go",
}

// ghostSynthDocPaths must not appear in active MASQUE docs (retired or never existed).
var ghostSynthDocPaths = []string{
	"connect_stream_hypothesis_test.go",
}

func findHiddifyAppRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := wd
	for range 12 {
		if _, err := os.Stat(filepath.Join(dir, "docs", "masque", "download-hypotheses.md")); err == nil {
			if _, err := os.Stat(filepath.Join(dir, "hiddify-core", "hiddify-sing-box", "go.mod")); err == nil {
				return dir
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("hiddify-app root not found")
	return ""
}

func readMasqueDoc(t *testing.T, root, rel string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(data)
}

// TestMasqueDocSynthAnchorPathsExist (H-S21) ensures synth anchor test files exist on disk.
func TestMasqueDocSynthAnchorPathsExist(t *testing.T) {
	t.Parallel()
	root := findHiddifyAppRoot(t)
	masqueDir := filepath.Join(root, "hiddify-core", "hiddify-sing-box", "transport", "masque")
	for _, name := range requiredSynthAnchorFiles {
		path := filepath.Join(masqueDir, name)
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("required synth anchor missing: %s", path)
		}
	}
}

// TestMasqueDocSynthAnchorPathsNoGhosts (H-S21) rejects retired ghost paths in active MASQUE docs.
func TestMasqueDocSynthAnchorPathsNoGhosts(t *testing.T) {
	t.Parallel()
	root := findHiddifyAppRoot(t)
	docs := []string{
		"docs/masque/download-hypotheses.md",
		"docs/masque/P0-download-analysis.md",
		"docs/masque/layers/30-connect-stream.md",
		"docs/masque/SYNTH-TEST-PLAN.md",
	}
	for _, rel := range docs {
		body := readMasqueDoc(t, root, rel)
		for _, ghost := range ghostSynthDocPaths {
			if strings.Contains(body, ghost) {
				t.Errorf("%s: ghost synth path %q must be removed or replaced", rel, ghost)
			}
		}
	}
	for _, name := range requiredSynthAnchorFiles {
		body := readMasqueDoc(t, root, "docs/masque/download-hypotheses.md")
		if !strings.Contains(body, name) {
			t.Errorf("download-hypotheses.md missing anchor reference %q", name)
		}
	}
	if body := readMasqueDoc(t, root, "docs/masque/download-hypotheses.md"); !strings.Contains(body, "BypassMatrix") {
		t.Error("download-hypotheses.md missing BypassMatrix synth anchor reference")
	}
}
