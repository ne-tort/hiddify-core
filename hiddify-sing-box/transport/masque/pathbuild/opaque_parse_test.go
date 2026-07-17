package pathbuild_test

import (
	"net/http"
	"testing"

	"github.com/sagernet/sing-box/protocol/masque/server/connectstream"
	"github.com/sagernet/sing-box/transport/masque/pathbuild"
	"github.com/yosida95/uritemplate/v3"
)

func TestOpaquePathRoundTripParse(t *testing.T) {
	cfg := pathbuild.ConfigFromOptions("", "", "", true)
	raw, err := pathbuild.FullURITemplate("127.0.0.1:443", pathbuild.PlaneTCP, cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	tpl, err := uritemplate.New(raw)
	if err != nil {
		t.Fatal(err)
	}
	expanded, err := pathbuild.ExpandHostPort(tpl, pathbuild.ActiveKey(true), "192.0.2.10", 8443)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodConnect, expanded, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "127.0.0.1:443"
	req.RequestURI = req.URL.RequestURI()
	host, port, err := connectstream.ParseTCPTargetFromRequest(req, tpl, true)
	if err != nil {
		t.Fatalf("parse: %v expanded=%s", err, expanded)
	}
	if host != "192.0.2.10" || port != "8443" {
		t.Fatalf("got %s:%s", host, port)
	}
	// Without obfuscation flag, opaque must fail
	if _, _, err := connectstream.ParseTCPTargetFromRequest(req, tpl, false); err == nil {
		t.Fatal("expected fail when obfuscation disabled")
	}
}
