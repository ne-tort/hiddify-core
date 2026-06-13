package server

import (
	_ "embed"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

//go:embed connect_stream.go
var connectStreamGoSource string

// TestConnectStreamServerWireContract (S74) locks CLIENT-SERVER-CONTRACTS § CONNECT-stream server invariants.
func TestConnectStreamServerWireContract(t *testing.T) {
	t.Parallel()
	contracts := readConnectStreamContractsDoc(t)

	requireContractSubstrings(t, connectStreamGoSource, "connect_stream.go",
		`r.Method != http.MethodConnect`,
		`r.Header.Get(":protocol")`,
		`ParseTCPTargetFromRequest`,
		`ResolveTCPTargetForDial`,
		`AllowTCPPort`,
		`relay.TuneTCPOutbound`,
		`EnableFullDuplex()`,
		`WriteHeader(http.StatusOK)`,
		`relay.TCPForward`,
	)
	if strings.Contains(connectStreamGoSource, "forwarder") {
		t.Fatal("CONNECT-stream template handler must not use forwarder (L3b only)")
	}
	if strings.Contains(connectStreamGoSource, "connectudp") {
		t.Fatal("CONNECT-stream template handler must not use connectudp (L4 only)")
	}

	idxDuplex := strings.Index(connectStreamGoSource, "EnableFullDuplex()")
	idxHeader := strings.Index(connectStreamGoSource, "WriteHeader(http.StatusOK)")
	idxRelay := strings.Index(connectStreamGoSource, "relay.TCPForward")
	if idxDuplex < 0 || idxHeader < 0 || idxRelay < 0 {
		t.Fatal("connect_stream.go: missing full-duplex / WriteHeader / relay ordering anchors")
	}
	if idxDuplex > idxHeader || idxHeader > idxRelay {
		t.Fatalf("wire order want EnableFullDuplex < WriteHeader < relay.TCPForward; got %d %d %d",
			idxDuplex, idxHeader, idxRelay)
	}

	requireContractSubstrings(t, contracts, "CLIENT-SERVER-CONTRACTS CONNECT-stream",
		"## CONNECT-stream (L2)",
		"`server/connect_stream.go`",
		"`relay.TCPTunnel`",
		"full-duplex",
		"TestConnectStreamServerWireContract",
	)
}

// TestConnectStreamServerUsesRelayNotForwarder (S40) locks CONNECT-stream L2 termination via relay, not L3 forwarder.
func TestConnectStreamServerUsesRelayNotForwarder(t *testing.T) {
	t.Parallel()
	if strings.Contains(connectStreamGoSource, "forwarder") {
		t.Fatal("CONNECT-stream template handler must not use forwarder (L3b only)")
	}
	if strings.Contains(connectStreamGoSource, "fwd.") {
		t.Fatal("CONNECT-stream template handler must not import transport/masque/forwarder")
	}
	requireContractSubstrings(t, connectStreamGoSource, "connect_stream.go",
		`"github.com/sagernet/sing-box/protocol/masque/relay"`,
		`relay.TuneTCPOutbound`,
		`relay.TCPForward`,
	)
}

func readConnectStreamContractsDoc(t *testing.T) string {
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
