package connectip

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestConnectIPPathIsolation guards P-IP package tree from P-UDP/P-STREAM imports (W-IP-0 PR0).
func TestConnectIPPathIsolation(t *testing.T) {
	t.Parallel()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Dir(filename)
	forbidden := []string{
		"github.com/sagernet/sing-box/transport/masque/stream",
		"github.com/sagernet/sing-box/transport/masque/connectudp",
	}
	var violations []string
	walkErr := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "inttest" {
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
		for _, imp := range forbidden {
			if strings.Contains(string(data), imp) {
				violations = append(violations, filepath.ToSlash(path)+": imports "+imp)
			}
		}
		return nil
	})
	if walkErr != nil {
		t.Fatal(walkErr)
	}
	if len(violations) > 0 {
		t.Fatalf("connectip path isolation violated:\n%s", strings.Join(violations, "\n"))
	}
}
