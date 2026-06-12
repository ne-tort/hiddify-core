package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestMasqueListenAddrDefaultHost(t *testing.T) {
	t.Parallel()
	if got := MasqueListenAddr("", 8443); got != "0.0.0.0:8443" {
		t.Fatalf("MasqueListenAddr empty host = %q want 0.0.0.0:8443", got)
	}
	if got := MasqueListenAddr("127.0.0.1", 443); got != "127.0.0.1:443" {
		t.Fatalf("MasqueListenAddr explicit host = %q want 127.0.0.1:443", got)
	}
}

func TestAuthorityStartupFlags(t *testing.T) {
	t.Parallel()
	h3Only, minimal := AuthorityStartupFlags(option.MasqueTCPRelayAuthority, option.MasqueEndpointOptions{})
	if !h3Only || !minimal {
		t.Fatalf("authority relay empty templates: h3Only=%v minimal=%v want true,true", h3Only, minimal)
	}
	h3Only, minimal = AuthorityStartupFlags(option.MasqueTCPRelayAuthority, option.MasqueEndpointOptions{
		TemplateUDP: "/masque/udp",
	})
	if !h3Only || minimal {
		t.Fatalf("authority relay with UDP template: h3Only=%v minimal=%v want true,false", h3Only, minimal)
	}
	h3Only, minimal = AuthorityStartupFlags(option.MasqueTCPRelayTemplate, option.MasqueEndpointOptions{})
	if h3Only || minimal {
		t.Fatalf("connect-stream relay: h3Only=%v minimal=%v want false,false", h3Only, minimal)
	}
}

func TestBuildStartupHandlerAuthorityMinimal(t *testing.T) {
	t.Parallel()
	handler, err := BuildStartupHandler(MuxHost{
		Options: option.MasqueEndpointOptions{},
	}, option.MasqueTCPRelayAuthority, option.MasqueEndpointOptions{})
	if err != nil {
		t.Fatalf("BuildStartupHandler: %v", err)
	}
	req := httptest.NewRequest(http.MethodConnect, "https://example.com:443/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("authority minimal CONNECT status=%d want 502 (no onward dial in test)", rec.Code)
	}
}
