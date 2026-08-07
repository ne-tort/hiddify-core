package ray2sing_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hiddify/ray2sing/ray2sing"
)

// Synthetic fixtures live in the Flutter repo; resolve relative to this module.
func fixturesRoot(t *testing.T) string {
	t.Helper()
	candidates := []string{
		filepath.Join("..", "..", "..", "test", "fixtures", "profile_import"),
		filepath.Join("..", "..", "test", "fixtures", "profile_import"),
	}
	wd, _ := os.Getwd()
	for _, c := range candidates {
		p := filepath.Clean(filepath.Join(wd, c))
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			return p
		}
	}
	t.Fatalf("fixtures dir not found from %s", wd)
	return ""
}

func TestSynthShareLinkFixtures(t *testing.T) {
	root := fixturesRoot(t)
	dir := filepath.Join(root, "share_links")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var failed []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".txt") {
			continue
		}
		name := e.Name()
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		opts, err := ray2sing.Ray2SingboxOptions(t.Context(), string(raw), false)
		if err != nil {
			failed = append(failed, name+": "+err.Error())
			continue
		}
		if opts == nil {
			failed = append(failed, name+": nil options")
			continue
		}
		n := len(opts.Outbounds) + len(opts.Endpoints)
		if n == 0 {
			failed = append(failed, name+": zero outbounds/endpoints")
		}
	}
	if len(failed) > 0 {
		t.Fatalf("share link fixtures failed:\n%s", strings.Join(failed, "\n"))
	}
}

func TestSynthWireGuardConf(t *testing.T) {
	root := fixturesRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "wireguard", "wg0.conf"))
	if err != nil {
		t.Fatal(err)
	}
	opts, err := ray2sing.Ray2SingboxOptions(t.Context(), string(raw), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(opts.Endpoints) == 0 && len(opts.Outbounds) == 0 {
		t.Fatal("expected wireguard endpoint")
	}
}
