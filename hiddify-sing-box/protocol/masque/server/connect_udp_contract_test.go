package server

import (
	_ "embed"
	"strings"
	"testing"
)

//go:embed connectudp/handler.go
var connectUDPHandlerSource string

//go:embed connect_udp.go
var connectUDPGoSource string

// TestConnectUDPServerWireContract (UDP-SRV-16) locks CLIENT-SERVER-CONTRACTS § CONNECT-UDP server invariants.
func TestConnectUDPServerWireContract(t *testing.T) {
	t.Parallel()
	contracts := readMasqueContractsDoc(t)

	requireContractSubstrings(t, connectUDPHandlerSource, "connectudp/handler.go",
		`udpProxy.Proxy`,
		`Hooks.ResolveTCPTarget`,
		`Hooks.AllowTCPPort`,
		`RequestProtocol`,
		`cudph2.ServeConnectUDP`,
	)
	if strings.Contains(connectUDPHandlerSource, "connectstream") {
		t.Fatal("CONNECT-UDP handler must not use connectstream (L2 only)")
	}
	if strings.Contains(connectUDPHandlerSource, "forwarder") {
		t.Fatal("CONNECT-UDP template handler must not use forwarder (L3b only)")
	}
	for _, forbidden := range []string{
		"github.com/sagernet/sing-box/third_party/masque-go",
		"masque.Proxy",
		"masque.NewProxy",
	} {
		if strings.Contains(connectUDPHandlerSource, forbidden) {
			t.Fatalf("connectudp/handler.go must not reference fork proxy %q (G8)", forbidden)
		}
	}
	if !strings.Contains(connectUDPHandlerSource, "cudprelay \"github.com/sagernet/sing-box/transport/masque/connectudp/relay\"") {
		t.Fatal("connectudp/handler.go must import connectudp/relay for prod H3 relay")
	}

	requireContractSubstrings(t, connectUDPGoSource, "connect_udp.go",
		`defaultConnectUDPHandler`,
		`ResolveTCPTargetForDial`,
		`AllowTCPPort`,
		`HandleConnectUDP`,
	)

	requireContractSubstrings(t, contracts, "CLIENT-SERVER-CONTRACTS CONNECT-UDP",
		"## CONNECT-UDP (L4)",
		"`HandleConnectUDP`",
		"`protocol/masque/server/connect_udp.go`",
		"TestConnectUDPServerWireContract",
	)
}
