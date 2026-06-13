package server

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestPrepareMasqueStartupTLS_nilInboundRejected(t *testing.T) {
	t.Parallel()
	_, err := PrepareMasqueStartupTLS(StartupTLSConfig{
		Ctx:        context.Background(),
		InboundTLS: nil,
		HTTPLayer:  option.MasqueHTTPLayerH3,
	})
	if err == nil {
		t.Fatal("expected error for nil inbound tls")
	}
}
