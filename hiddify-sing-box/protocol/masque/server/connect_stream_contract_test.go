package server

import (
	_ "embed"
	"strings"
	"testing"
)

//go:embed connectstream/handler.go
var connectStreamGoSource string

// TestConnectStreamServerWireContract (S74) locks CLIENT-SERVER-CONTRACTS § CONNECT-stream server invariants.
func TestConnectStreamServerWireContract(t *testing.T) {
	t.Parallel()
	contracts := readMasqueContractsDoc(t)

	requireContractSubstrings(t, connectStreamGoSource, "connectstream/handler.go",
		`r.Method != http.MethodConnect`,
		`r.Header.Get(":protocol")`,
		`ConnectTCPProtocol`,
		`ParseTCPTargetFromRequest`,
		`Hooks.ResolveTCPTargetAddrs`,
		`Hooks.DialTCPTargetSerial`,
		`Hooks.AllowTCPPort`,
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
		t.Fatal("connectstream/handler.go: missing full-duplex / WriteHeader / relay ordering anchors")
	}
	if idxDuplex > idxHeader || idxHeader > idxRelay {
		t.Fatalf("wire order want EnableFullDuplex < WriteHeader < relay.TCPForward; got %d %d %d",
			idxDuplex, idxHeader, idxRelay)
	}

	requireContractSubstrings(t, contracts, "CLIENT-SERVER-CONTRACTS CONNECT-stream",
		"## CONNECT-stream (L2)",
		"`server/connectstream/handler.go`",
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
	requireContractSubstrings(t, connectStreamGoSource, "connectstream/handler.go",
		`"github.com/sagernet/sing-box/protocol/masque/relay"`,
		`relay.TuneTCPOutbound`,
		`relay.TCPForward`,
	)
}

