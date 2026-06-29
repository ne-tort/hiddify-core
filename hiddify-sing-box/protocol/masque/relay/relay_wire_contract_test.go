package relay

import (
	_ "embed"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

//go:embed tcp.go
var tcpGoSource string

//go:embed tune.go
var tuneGoSource string

func requireContractSubstrings(t *testing.T, haystack, label string, subs ...string) {
	t.Helper()
	for _, sub := range subs {
		if !strings.Contains(haystack, sub) {
			t.Fatalf("%s: missing contract substring %q", label, sub)
		}
	}
}

func readRelayContractsDoc(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := wd
	for range 10 {
		path := filepath.Join(dir, "docs", "masque", "layers", "CLIENT-SERVER-CONTRACTS.md")
		if data, err := os.ReadFile(path); err == nil {
			return string(data)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("CLIENT-SERVER-CONTRACTS.md not found (run from hiddify-app checkout)")
	return ""
}

// TestRelayTCPForwardWireContract (H-L5) locks CONNECT-stream server relay symbols in code + contracts doc.
func TestRelayTCPForwardWireContract(t *testing.T) {
	t.Parallel()
	contracts := readRelayContractsDoc(t)

	requireContractSubstrings(t, tcpGoSource, "tcp.go",
		`func TCPForward`,
		`RelayTCPTunnel`,
	)
	requireContractSubstrings(t, tuneGoSource, "tune.go",
		`func TuneTCPOutbound`,
		`SetNoDelay(true)`,
		`SetReadBuffer(TCPKernelBuf)`,
		`SetWriteBuffer(TCPKernelBuf)`,
	)

	requireContractSubstrings(t, contracts, "CLIENT-SERVER-CONTRACTS CONNECT-stream relay",
		"## CONNECT-stream (L2)",
		"`relay.TCPForward`",
		"`relay.TuneTCPOutbound`",
		"TestRelayTCPForwardWireContract",
	)
}
