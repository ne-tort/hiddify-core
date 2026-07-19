package masque

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var connectIPProdForbiddenEnv = regexp.MustCompile(`os\.(Getenv|LookupEnv)\(`)

func TestGATEConnectIPProdZeroEnvPackage(t *testing.T) {
	t.Parallel()
	root := filepath.Join("connectip")
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
		if connectIPProdForbiddenEnv.Match(data) {
			violations = append(violations, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) > 0 {
		t.Fatalf("connectip prod sources must not use getenv: %v", violations)
	}
}

func TestGATEConnectIPProdZeroEnvMasqueRoot(t *testing.T) {
	t.Parallel()
	matches, err := filepath.Glob("connectip_*.go")
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
		if connectIPProdForbiddenEnv.Match(data) {
			violations = append(violations, path)
		}
	}
	if len(violations) > 0 {
		t.Fatalf("masque connectip_* prod sources must not use getenv: %v", violations)
	}
}

func TestGATEConnectIPProdZeroEnvProtocol(t *testing.T) {
	t.Parallel()
	protoDir := filepath.Join("..", "..", "protocol", "masque")
	globs := []string{
		filepath.Join(protoDir, "connect_ip*.go"),
		filepath.Join(protoDir, "server", "connect_ip*.go"),
	}
	var violations []string
	for _, pattern := range globs {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range matches {
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if connectIPProdForbiddenEnv.Match(data) {
				violations = append(violations, path)
			}
		}
	}
	if len(violations) > 0 {
		t.Fatalf("protocol/masque connect_ip (+ server/) prod sources must not use getenv: %v", violations)
	}
}
