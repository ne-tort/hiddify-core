package masque

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

var (
	masqueGetenvLiteralRe = regexp.MustCompile(`os\.Getenv\(\s*"((?:MASQUE|HIDDIFY_MASQUE)_[^"]+)"`)
	masqueConstSingleRe   = regexp.MustCompile(`const\s+(?:\w+\s+)?\w+\s*=\s*"((?:MASQUE|HIDDIFY_MASQUE)_[^"]+)"`)
	masqueConstGroupRe    = regexp.MustCompile(`(?m)^\s+\w+\s*=\s*"((?:MASQUE|HIDDIFY_MASQUE)_[^"]+)"`)
)

// TestMasqueDocumentedEnvVarsExist (H-S22) — every documented MASQUE knob is read in prod Go, and vice versa.
func TestMasqueDocumentedEnvVarsExist(t *testing.T) {
	t.Parallel()
	root := masquePackageRoot(t)
	prodEnv := collectMasqueProdEnvVars(t, root)

	doc := make(map[string]struct{}, len(MasqueDocumentedEnvVars))
	for _, name := range MasqueDocumentedEnvVars {
		doc[name] = struct{}{}
	}

	var undocumented []string
	for name := range prodEnv {
		if _, ok := doc[name]; !ok {
			undocumented = append(undocumented, name)
		}
	}
	sort.Strings(undocumented)
	if len(undocumented) > 0 {
		t.Fatalf("prod os.Getenv references not in MasqueDocumentedEnvVars:\n%s", strings.Join(undocumented, "\n"))
	}

	var missing []string
	for _, name := range MasqueDocumentedEnvVars {
		if !prodEnv[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("MasqueDocumentedEnvVars not referenced in prod masque Go:\n%s", strings.Join(missing, "\n"))
	}
}

func masquePackageRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Dir(filename)
}

func collectMasqueProdEnvVars(t *testing.T, root string) map[string]bool {
	t.Helper()
	found := make(map[string]bool)
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			base := d.Name()
			if base == "testdata" || base == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		src := stripGoLineComments(string(data))
		for _, m := range masqueGetenvLiteralRe.FindAllStringSubmatch(src, -1) {
			found[m[1]] = true
		}
		for _, m := range masqueConstSingleRe.FindAllStringSubmatch(src, -1) {
			found[m[1]] = true
		}
		for _, m := range masqueConstGroupRe.FindAllStringSubmatch(src, -1) {
			found[m[1]] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

func stripGoLineComments(src string) string {
	lines := strings.Split(src, "\n")
	for i, line := range lines {
		if idx := strings.Index(line, "//"); idx >= 0 {
			lines[i] = line[:idx]
		}
	}
	return strings.Join(lines, "\n")
}
