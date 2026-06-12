package h3

import (
	"strings"
	"testing"
)

// TestExpandAuthorityConnectURLSeparateFromTemplateTCP documents the authority URL boundary:
// connect_stream expands template_tcp via uritemplate + /tcp/ path fixes in masque core;
// connect_authority uses TemplateConnect + ExpandAuthorityConnectURL only (Invisv https://target:port/).
func TestExpandAuthorityConnectURLSeparateFromTemplateTCP(t *testing.T) {
	t.Parallel()
	u, err := ExpandAuthorityConnectURL("", "10.0.0.1", 8080)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(u.Path, "/tcp/") {
		t.Fatalf("authority default URL must not use connect_stream /tcp/ path: %s", u)
	}
	if u.String() != "https://10.0.0.1:8080/" {
		t.Fatalf("unexpected default: %s", u)
	}

	invisv, err := ExpandAuthorityConnectURL("https://{target_host}:{target_port}/", "edge.example", 443)
	if err != nil {
		t.Fatal(err)
	}
	if invisv.Host != "edge.example:443" || invisv.Path != "/" {
		t.Fatalf("template_connect expansion: %s", invisv)
	}

	// template_tcp-style strings belong on connect_stream (uritemplate + path fixes), not here.
	tcpStyle := "https://masque.local/masque/tcp/{target_host}/{target_port}"
	expanded, err := ExpandAuthorityConnectURL(tcpStyle, "1.2.3.4", 443)
	if err != nil {
		t.Fatal(err)
	}
	want := "https://masque.local/masque/tcp/1.2.3.4/443"
	if expanded.String() != want {
		t.Fatalf("ExpandAuthorityConnectURL is plain substitution (%s), not template_tcp expansion", expanded)
	}
}

func TestExpandAuthorityConnectURLDefault(t *testing.T) {
	t.Parallel()
	u, err := ExpandAuthorityConnectURL("", "163.5.180.181", 5201)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "https" || u.Host != "163.5.180.181:5201" || u.Path != "/" {
		t.Fatalf("unexpected url: %s", u.String())
	}
}
