package session_test

import (
	_ "embed"
	"strings"
	"testing"
)

//go:embed http3_transport.go
var http3TransportProdSource string

// TestProdHTTP3TransportNoIPHTTPTCPHTTPEagerAlias locks X-11 / G7: prod must not assign TCPHTTP = IPHTTP.
func TestProdHTTP3TransportNoIPHTTPTCPHTTPEagerAlias(t *testing.T) {
	t.Parallel()
	if !strings.Contains(http3TransportProdSource, "s.TCPHTTP = NewTCPConnectStreamHTTP3Transport(s)") {
		t.Fatal("EnsureTCPHTTPTransport must allocate dedicated CONNECT-stream transport")
	}
	if strings.Contains(http3TransportProdSource, "s.TCPHTTP = s.IPHTTP") ||
		strings.Contains(http3TransportProdSource, "s.IPHTTP = s.TCPHTTP") {
		t.Fatal("prod http3_transport.go must not assign TCPHTTP and IPHTTP to the same pointer")
	}
}
