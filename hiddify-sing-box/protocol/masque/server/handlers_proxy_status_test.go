package server_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/masque/server"
)

func TestBuildMuxHandlerParseRejectWritesProxyStatus(t *testing.T) {
	t.Parallel()
	const tmpl = "https://masque.example:443/masque/udp/{target_host}/{target_port}/"
	host := server.MuxHost{
		Options: option.MasqueEndpointOptions{
			Listen:     "masque.example",
			ListenPort: 443,
			PathUDP:    "/masque/udp",
		},
		ResolveTemplates: func(option.MasqueEndpointOptions) (string, string, string) {
			return tmpl,
				"https://masque.example:443/.well-known/masque/ip/",
				"https://masque.example:443/.well-known/masque/tcp/{target_host}/{target_port}/"
		},
	}
	h, err := server.BuildMuxHandler(host, option.MasqueTCPRelayTemplate)
	if err != nil {
		t.Fatal(err)
	}
	// GET hits UDP mux path; ParseRequest rejects non-CONNECT (405) with Proxy-Status (F-PS-01).
	req := httptest.NewRequest(http.MethodGet, "/masque/udp/198.51.100.1/443/", nil)
	req.Host = "masque.example:443"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d want 405", rec.Code)
	}
	ps := rec.Header().Get("Proxy-Status")
	if ps == "" {
		t.Fatal("missing Proxy-Status on parse reject")
	}
	if !strings.Contains(ps, "masque.example") {
		t.Fatalf("Proxy-Status=%q want authority", ps)
	}
	if !strings.Contains(ps, "details=") {
		t.Fatalf("Proxy-Status=%q want details=", ps)
	}
}
