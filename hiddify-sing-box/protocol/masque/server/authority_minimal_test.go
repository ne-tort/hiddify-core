package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestAuthorityServerMinimalForOptionsEmptyTemplates(t *testing.T) {
	t.Parallel()
	if !AuthorityServerMinimalForOptions(option.MasqueEndpointOptions{}) {
		t.Fatal("empty UDP/IP templates must select authority minimal mux")
	}
	o := option.MasqueEndpointOptions{TemplateUDP: "https://x/{target}"}
	if AuthorityServerMinimalForOptions(o) {
		t.Fatal("non-empty TemplateUDP must not select authority minimal mux")
	}
}

func TestNewAuthorityMinimalHandlerRejectsNonConnect(t *testing.T) {
	t.Parallel()
	h := NewAuthorityMinimalHandler(TCPConnectAuthorityHost{})
	req := httptest.NewRequest(http.MethodGet, "https://example.test/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for GET, got %d", rr.Code)
	}
}
