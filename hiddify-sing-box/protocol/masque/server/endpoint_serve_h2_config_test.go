package server

import (
	_ "embed"
	"strings"
	"testing"
)

//go:embed endpoint_serve.go
var endpointServeSource string

// TestEndpointServeUsesH2BulkConfigDirect locks removal of h2_bulk_config_bridge:
// HTTP/2 collateral listener configures via transport/masque/h2, not transport/masque bridge.
func TestEndpointServeUsesH2BulkConfigDirect(t *testing.T) {
	t.Parallel()
	if strings.Contains(endpointServeSource, "MasqueBulkHTTP2ServerConfig") {
		t.Fatal("endpoint_serve must not use masque.MasqueBulkHTTP2ServerConfig bridge")
	}
	if !strings.Contains(endpointServeSource, "mh2.BulkHTTP2ServerConfigResolved") {
		t.Fatal("endpoint_serve must call h2.BulkHTTP2ServerConfigResolved (h2_tuning path)")
	}
}
