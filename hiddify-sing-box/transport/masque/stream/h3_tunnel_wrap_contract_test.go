package stream

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestH3ConnectTunnelFromResponseSingleWrapContract locks STR-4a7: h3 builds the impl conn only;
// stream.H3TunnelFromResponse owns the single stream.TunnelConn error shell.
func TestH3ConnectTunnelFromResponseSingleWrapContract(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	h3Tunnel := readMasqueSource(t, filepath.Join(root, "transport", "masque", "h3", "tunnel.go"))
	if strings.Contains(h3Tunnel, "strm.NewTunnelConn(") || strings.Contains(h3Tunnel, "return NewTunnelConn(") {
		t.Fatal("h3.ConnectTunnelFromResponse must not wrap stream.NewTunnelConn (double-wrap)")
	}
	h3Stream := readMasqueSource(t, filepath.Join(root, "transport", "masque", "stream", "h3_tunnel.go"))
	if !strings.Contains(h3Stream, "NewTunnelConn(inner)") {
		t.Fatal("stream.H3TunnelFromResponse must wrap tunnel with NewTunnelConn")
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for dir := wd; ; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		if filepath.Dir(dir) == dir {
			t.Fatal("go.mod not found")
		}
	}
}

func readMasqueSource(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(rel)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
