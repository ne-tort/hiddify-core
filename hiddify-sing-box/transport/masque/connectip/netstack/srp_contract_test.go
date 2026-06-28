package netstack

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestConnectIPNetstackSRPContract locks W-IP-1 file boundaries (IP-SOLID-02 AUDIT).
func TestConnectIPNetstackSRPContract(t *testing.T) {
	t.Parallel()
	layers := map[string][]string{
		"stack":    {"stack.go"},
		"egress":   {"egress.go"},
		"factory":  {"factory.go"},
		"prefix":   {"prefix.go", "prefix_listener.go"},
		"headroom": {"outbound_headroom.go"},
		"session":  {"session.go"},
		"hooks":    {"hooks.go"},
	}
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Dir(filename)
	for layer, files := range layers {
		for _, f := range files {
			path := filepath.Join(root, f)
			if _, err := os.Stat(path); err != nil {
				t.Fatalf("layer %q missing %s: %v", layer, f, err)
			}
		}
	}
	src, err := os.ReadFile(filepath.Join(root, "stack.go"))
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	for _, sym := range []string{"type Netstack struct", "func (s *Netstack) Close", "func (s *Netstack) DialContext"} {
		if !strings.Contains(body, sym) {
			t.Fatalf("stack.go must own %q", sym)
		}
	}
	egress, err := os.ReadFile(filepath.Join(root, "egress.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, sym := range []string{"func (s *Netstack) WriteNotify", "func (s *Netstack) runExclusiveOutboundDrain", "IsRetryablePacketWriteError"} {
		if !strings.Contains(string(egress), sym) {
			t.Fatalf("egress.go must own %q", sym)
		}
	}
}
