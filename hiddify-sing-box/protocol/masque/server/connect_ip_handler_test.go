package server

import (
	_ "embed"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	connectipgo "github.com/quic-go/connect-ip-go"
	cipserver "github.com/sagernet/sing-box/protocol/masque/server/connectip"
)

//go:embed connectip/handler.go
var connectIPHandlerGoSource string

//go:embed connect_ip_handler.go
var connectIPHandlerShellSource string

func TestConnectIPHandlerSourceBlocksOnRouteConnectIPBlocked(t *testing.T) {
	t.Parallel()
	if !strings.Contains(connectIPHandlerGoSource, "Hooks.RouteBlocked") {
		t.Fatal("CONNECT-IP handler must block until RouteBlocked returns (H2/H3 parity)")
	}
	if strings.Contains(connectIPHandlerGoSource, "go Hooks.RouteBlocked") {
		t.Fatal("CONNECT-IP handler must not spawn RouteBlocked in background")
	}
	if !strings.Contains(connectIPHandlerShellSource, "RouteConnectIPBlocked(") {
		t.Fatal("CONNECT-IP shell must call RouteConnectIPBlocked synchronously")
	}
	if strings.Contains(connectIPHandlerShellSource, "go RouteConnectIPBlocked") {
		t.Fatal("CONNECT-IP shell must not spawn RouteConnectIPBlocked in background")
	}
}

func TestConnectIPHandlerSourceNoPostProxyBadGateway(t *testing.T) {
	t.Parallel()
	if strings.Contains(connectIPHandlerGoSource, "w.WriteHeader(http.StatusBadGateway)") {
		t.Fatal("CONNECT-IP handler must not WriteHeader(502) after Proxy committed 200 (UDP-BUG-09 class)")
	}
}

func TestConnectIPProxySharedSingletonStateless(t *testing.T) {
	t.Parallel()
	var p connectipgo.Proxy
	if unsafe.Sizeof(p) != 0 {
		t.Fatalf("connectip.Proxy must remain stateless (zero-size); got size %d", unsafe.Sizeof(p))
	}
	if cipserver.SharedProxy() == nil {
		t.Fatal("SharedProxy must be initialized")
	}
	typ := reflect.TypeOf(connectipgo.Proxy{})
	if typ.NumField() != 0 {
		t.Fatalf("connectip.Proxy must have no fields; got %d", typ.NumField())
	}
}

// TestConnectIPServerWireContract (IP-SRV-02) locks CLIENT-SERVER-CONTRACTS § CONNECT-IP server invariants.
func TestConnectIPServerWireContract(t *testing.T) {
	t.Parallel()
	contracts := readMasqueContractsDoc(t)

	requireContractSubstrings(t, connectIPHandlerGoSource, "connectip/handler.go",
		`connectipgo.ParseRequest`,
		`sharedConnectIPProxy.Proxy`,
		`AssignAddresses`,
		`AdvertiseRoute`,
		`Hooks.RouteBlocked`,
		`Hooks.RouteSetupTimeout`,
		`Hooks.RequestErrorHTTPStatus`,
	)
	if strings.Contains(connectIPHandlerGoSource, "relay.TCPTunnel") {
		t.Fatal("CONNECT-IP handler must not use relay.TCPTunnel")
	}
	if strings.Contains(connectIPHandlerGoSource, "relay/") {
		t.Fatal("CONNECT-IP handler must not import protocol/masque/relay")
	}
	if strings.Contains(connectIPHandlerGoSource, "fwd.") {
		t.Fatal("CONNECT-IP handler must not import transport/masque/forwarder (L3b terminates in connect_ip.go)")
	}

	requireContractSubstrings(t, connectIPHandlerShellSource, "connect_ip_handler.go",
		`defaultConnectIPHandler`,
		`ConnectIPRequestErrorHTTPStatus`,
		`RouteConnectIPBlocked`,
		`HandleConnectIPRequest`,
	)

	requireContractSubstrings(t, contracts, "CLIENT-SERVER-CONTRACTS CONNECT-IP",
		"## CONNECT-IP (L3a + L3b)",
		"`server/connectip/handler.go`",
		"`protocol/masque/server/connect_ip_handler.go`",
		"TestConnectIPServerWireContract",
	)
}
