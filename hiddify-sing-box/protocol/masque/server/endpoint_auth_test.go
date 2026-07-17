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
	req := httptest.NewRequest(http.MethodGet, "https://masque.local/.well-known/masque/udp/*", nil)
	var compiled *auth.Compiled
	if !AuthorizeMasqueRequest(req, &compiled, option.MasqueEndpointOptions{}, false) {
		t.Fatal("expected allow when no auth configured and endpoint not started")
	}
}

func TestAuthorizeMasqueRequestLazyCompileInvalidConfigFailClosed(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "https://masque.local/masque/ip/*", nil)
	var compiled *auth.Compiled
	opts := option.MasqueEndpointOptions{
		ServerAuth: &option.MasqueServerAuthOptions{
			Policy: "not-a-policy",
		},
	}
	if AuthorizeMasqueRequest(req, &compiled, opts, false) {
		t.Fatal("expected deny on lazy compile failure when endpoint not started")
	}
	if compiled != nil {
		t.Fatal("compiled auth must stay nil after compile failure")
	}
}

func TestAuthorizeMasqueRequestLazyCompileStoresValidAuth(t *testing.T) {
	t.Parallel()
	token := "lazy-token"
	req := httptest.NewRequest(http.MethodGet, "https://masque.local/.well-known/masque/udp/*", nil)
	var compiled *auth.Compiled
	opts := option.MasqueEndpointOptions{
		ServerAuth: &option.MasqueServerAuthOptions{
			BearerTokens: []string{token},
		},
	}
	if AuthorizeMasqueRequest(req, &compiled, opts, false) {
		t.Fatal("expected deny without bearer token after lazy compile")
	}
	if compiled == nil {
		t.Fatal("expected compiled auth cached after lazy compile")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if !AuthorizeMasqueRequest(req, &compiled, opts, false) {
		t.Fatal("expected allow with bearer token after lazy compile cache")
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
	req := httptest.NewRequest(http.MethodGet, "https://masque.local/.well-known/masque/udp/*", nil)
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
