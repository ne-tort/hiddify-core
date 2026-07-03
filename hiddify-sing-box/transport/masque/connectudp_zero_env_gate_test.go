package masque

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var connectUDPProdForbiddenEnv = regexp.MustCompile(`os\.(Getenv|LookupEnv)\(`)

func TestGATEConnectUDPProdZeroEnvPackage(t *testing.T) {
	t.Parallel()
	root := filepath.Join("connectudp")
	var violations []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if connectUDPProdForbiddenEnv.Match(data) {
			violations = append(violations, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) > 0 {
		t.Fatalf("connectudp prod sources must not use getenv: %v", violations)
	}
}

func TestGATEConnectUDPProdZeroEnvMasqueRoot(t *testing.T) {
	t.Parallel()
	matches, err := filepath.Glob("connectudp_*.go")
	if err != nil {
		t.Fatal(err)
	}
	var violations []string
	for _, path := range matches {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if connectUDPProdForbiddenEnv.Match(data) {
			violations = append(violations, path)
		}
	}
	if len(violations) > 0 {
		t.Fatalf("masque connectudp_* prod sources must not use getenv: %v", violations)
	}
}
