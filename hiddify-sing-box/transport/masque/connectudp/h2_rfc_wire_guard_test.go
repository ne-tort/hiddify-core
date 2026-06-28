package connectudp

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func connectUDPH2ProdSources(t *testing.T) map[string]string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Clean(filepath.Join(filepath.Dir(file), "h2"))
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read h2 dir: %v", err)
	}
	out := make(map[string]string)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		out[e.Name()] = string(b)
	}
	return out
}

// TestConnectUDPH2ProdTreeNoInvisvDraft03Wire locks X-07: prod CONNECT-UDP H2 tree excludes Invisv draft-03 TLV path.
func TestConnectUDPH2ProdTreeNoInvisvDraft03Wire(t *testing.T) {
	t.Parallel()
	forbidden := []string{
		"draft-03",
		"masque-draft",
		"Datagram-Flow-Id",
		"StreamDataToDatagramChunk",
	}
	for name, src := range connectUDPH2ProdSources(t) {
		for _, sym := range forbidden {
			if strings.Contains(src, sym) {
				t.Fatalf("connectudp/h2/%s must not reference Invisv draft-03 symbol %q", name, sym)
			}
		}
	}
}
