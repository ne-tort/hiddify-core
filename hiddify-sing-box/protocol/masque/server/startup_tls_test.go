package server

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestPrepareMasqueStartupTLS_nilInboundRejected(t *testing.T) {
	t.Parallel()
	_, err := PrepareMasqueStartupTLS(StartupTLSConfig{
		Ctx:              context.Background(),
		InboundTLS:       nil,
		HTTPLayer:        option.MasqueHTTPLayerH3,
		AuthorityH3Only:  false,
		AuthorityMinimal: false,
	})
	if err == nil {
		t.Fatal("expected error for nil inbound tls")
	}
}

func TestPrepareMasqueStartupTLS_authorityStdPathsRequired(t *testing.T) {
	t.Setenv("MASQUE_SERVER_STD_TLS", "1")
	_, err := PrepareMasqueStartupTLS(StartupTLSConfig{
		Ctx:              context.Background(),
		InboundTLS:       &option.InboundTLSOptions{},
		HTTPLayer:        option.MasqueHTTPLayerH3,
		AuthorityH3Only:  true,
		AuthorityMinimal: true,
	})
	if err == nil {
		t.Fatal("expected error when std tls paths missing")
	}
}
