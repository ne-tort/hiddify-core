package masque

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var masqueEnvLiteralRE = regexp.MustCompile(`"(?:MASQUE|HIDDIFY_MASQUE)_[A-Z0-9_]+"`)

// masqueEnvTestOnlyVars are referenced only from tests, live probes, or artifact dumps.
var masqueEnvTestOnlyVars = map[string]struct{}{
	"MASQUE_LIVE_BASIC_PASS":                        {},
	"MASQUE_LIVE_BASIC_USER":                        {},
	"MASQUE_LIVE_SERVER":                            {},
	"MASQUE_LIVE_SERVER_PORT":                       {},
	"MASQUE_LIVE_TOKEN":                             {},
	"MASQUE_LIVE_UDP_TARGET_HOST":                   {},
	"MASQUE_LIVE_UDP_TARGET_LOCAL_TCP":              {},
	"MASQUE_LIVE_UDP_TARGET_PORT":                   {},
	"MASQUE_MALFORMED_SCOPED_ARTIFACT_PATH":         {},
	"MASQUE_MALFORMED_SCOPED_TRANSPORT_ARTIFACT_PATH": {},
	"MASQUE_PEER_ABORT_ARTIFACT_PATH":               {},
	"MASQUE_ROUTE_ADVERTISE_ARTIFACT_PATH":          {},
	"MASQUE_STRESS":                                 {},
	"MASQUE_STRESS_SHAPED_MBIT":                     {},
}

func findSingBoxRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := wd
	for range 12 {
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

func collectMasqueEnvLiterals(t *testing.T, root string, prodOnly bool) map[string]struct{} {
	t.Helper()
	found := make(map[string]struct{})
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			base := d.Name()
			if base == "vendor" || base == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if prodOnly {
			if strings.HasSuffix(path, "_test.go") {
				return nil
			}
			if strings.Contains(path, string(filepath.Separator)+"third_party"+string(filepath.Separator)+"masque-go"+string(filepath.Separator)) {
				return nil
			}
		}
		if strings.HasSuffix(path, string(filepath.Separator)+"documented_env_vars.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range masqueEnvLiteralRE.FindAllString(string(data), -1) {
			name := strings.Trim(m, `"`)
			found[name] = struct{}{}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return found
}

// TestMasqueDocumentedEnvVarsExist (H-S22): every registered knob appears as a string literal in prod Go.
func TestMasqueDocumentedEnvVarsExist(t *testing.T) {
	t.Parallel()
	root := findSingBoxRoot(t)
	prod := collectMasqueEnvLiterals(t, root, true)
	for _, name := range MasqueDocumentedEnvVars {
		if _, ok := prod[name]; !ok {
			t.Errorf("documented env %q missing from production Go sources", name)
		}
	}
}

// TestMasqueDocumentedEnvVarsComplete guards registry drift: prod literals must be documented or test-only.
func TestMasqueDocumentedEnvVarsComplete(t *testing.T) {
	t.Parallel()
	root := findSingBoxRoot(t)
	prod := collectMasqueEnvLiterals(t, root, true)
	doc := make(map[string]struct{}, len(MasqueDocumentedEnvVars))
	for _, name := range MasqueDocumentedEnvVars {
		doc[name] = struct{}{}
	}
	var undocumented []string
	for name := range prod {
		if _, ok := doc[name]; ok {
			continue
		}
		if _, ok := masqueEnvTestOnlyVars[name]; ok {
			continue
		}
		undocumented = append(undocumented, name)
	}
	sort.Strings(undocumented)
	if len(undocumented) > 0 {
		t.Fatalf("production env literals not in MasqueDocumentedEnvVars: %v", undocumented)
	}
}
