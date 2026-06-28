package connectudp

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestConnectUDPPathIsolation guards P-UDP package tree from P-STREAM/P-IP imports (W-UDP-4 PR0).
func TestConnectUDPPathIsolation(t *testing.T) {
	t.Parallel()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Dir(filename)
	forbidden := []string{
		"github.com/sagernet/sing-box/transport/masque/stream",
		"github.com/sagernet/sing-box/transport/masque/connectip",
	}
	var violations []string
	walkErr := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
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
		t.Fatalf("connectudp path isolation violated:\n%s", strings.Join(violations, "\n"))
	}
}
