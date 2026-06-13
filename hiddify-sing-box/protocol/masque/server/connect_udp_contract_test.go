package server

import (
	_ "embed"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

//go:embed connect_udp.go
var connectUDPGoSource string

// TestConnectUDPWireContract locks CLIENT-SERVER-CONTRACTS § L4 wire invariants.
func TestConnectUDPWireContract(t *testing.T) {
	t.Parallel()
	contracts := readConnectUDPContractsDoc(t)

	requireContractSubstrings(t, connectUDPGoSource, "connect_udp.go",
		`masqueRequestProtocolConnectUDP = "connect-udp"`,
		"udpProxy.Proxy(w, parsed)",
		"cudp.ServeH2(w, r, conn)",
		"EnableFullDuplex()",
		"CapsuleProtocolHeader",
		"ConnectUDPTargetPolicy",
		"checkConnectUDPTargetPolicy",
	)
	if strings.Contains(connectUDPGoSource, "relay.TCPTunnel") {
		t.Fatal("CONNECT-UDP must not use relay.TCPTunnel (L2 stream only)")
	}

	requireContractSubstrings(t, contracts, "CLIENT-SERVER-CONTRACTS L4",
		"## CONNECT-UDP (L4)",
		"HandleConnectUDP",
		"connectudp.ServeH2",
		"DatagramSplitConn",
		"ErrPortUnreachable",
		"buildTemplates",
		"Authorize",
		"TestConnectUDPWireContract",
	)
}

func readConnectUDPContractsDoc(t *testing.T) string {
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

func requireContractSubstrings(t *testing.T, src, label string, parts ...string) {
	t.Helper()
	for _, part := range parts {
		if !strings.Contains(src, part) {
			t.Fatalf("%s: missing %q", label, part)
		}
	}
}
