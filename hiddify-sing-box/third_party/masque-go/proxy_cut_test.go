//go:build !masque_ref

package masque

import (
	"os"
	"strings"
	"testing"
)

// TestProxyGoCutFromDefaultBuild locks fork proxy.go behind masque_ref (W-UDP-1 hygiene).
func TestProxyGoCutFromDefaultBuild(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile("proxy.go")
	if err != nil {
		t.Fatalf("read proxy.go: %v", err)
	}
	head := string(b)
	if !strings.Contains(head, "//go:build masque_ref") {
		t.Fatal("proxy.go must be tagged //go:build masque_ref — prod dial uses connectudp/conn only")
	}
}
