package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/masque/auth"
)

func TestAuthorizeMasqueRequestNilCompiledNoAuthConfigured(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "https://masque.local/masque/udp/*", nil)
	var compiled *auth.Compiled
	if !AuthorizeMasqueRequest(req, &compiled, option.MasqueEndpointOptions{}, false) {
		t.Fatal("expected allow when no auth configured and endpoint not started")
	}
}

func TestAuthorizeMasqueRequestCompiledDeny(t *testing.T) {
	t.Parallel()
	token := "secret-token"
	compiled, err := auth.Compile(option.MasqueEndpointOptions{
		ServerAuth: &option.MasqueServerAuthOptions{
			BearerTokens: []string{token},
		},
	})
	if err != nil {
		t.Fatalf("compile auth: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "https://masque.local/masque/udp/*", nil)
	if AuthorizeMasqueRequest(req, &compiled, option.MasqueEndpointOptions{}, true) {
		t.Fatal("expected deny without bearer token")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if !AuthorizeMasqueRequest(req, &compiled, option.MasqueEndpointOptions{}, true) {
		t.Fatal("expected allow with matching bearer token")
	}
}

func TestBuildEndpointMuxHostWiresHooks(t *testing.T) {
	t.Parallel()
	called := false
	host := BuildEndpointMuxHost(EndpointMuxFields{
		Tag:  "test",
		Type: "masque",
		Hooks: TemplateAuthorityHooks{
			ResolveTemplates: func(option.MasqueEndpointOptions) (string, string, string) {
				called = true
				return "u", "i", "t"
			},
		},
	})
	if host.Tag != "test" || host.Type != "masque" {
		t.Fatalf("unexpected host identity: tag=%q type=%q", host.Tag, host.Type)
	}
	if host.ResolveTemplates == nil {
		t.Fatal("ResolveTemplates not wired")
	}
	host.ResolveTemplates(option.MasqueEndpointOptions{})
	if !called {
		t.Fatal("ResolveTemplates hook not invoked")
	}
}
