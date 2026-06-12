package server

import (
	"net/http"
	"net/url"
	"testing"
)

func TestParseCONNECTAuthorityTargetLoopbackWithPort(t *testing.T) {
	t.Parallel()
	req, err := http.NewRequest(http.MethodConnect, "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "127.0.0.1:5201"
	req.URL = &url.URL{Scheme: "https", Host: "127.0.0.1:5201", Path: "/"}
	host, port, err := ParseCONNECTAuthorityTarget(req)
	if err != nil {
		t.Fatal(err)
	}
	if host != "127.0.0.1" || port != "5201" {
		t.Fatalf("host=%q port=%q", host, port)
	}
}

func TestParseCONNECTAuthorityTargetHTTPSDefaultPort(t *testing.T) {
	t.Parallel()
	req, err := http.NewRequest(http.MethodConnect, "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "203.0.113.1"
	req.URL = &url.URL{Scheme: "https", Host: "203.0.113.1", Path: "/"}
	host, port, err := ParseCONNECTAuthorityTarget(req)
	if err != nil {
		t.Fatal(err)
	}
	if host != "203.0.113.1" || port != "443" {
		t.Fatalf("host=%q port=%q", host, port)
	}
}

func TestParseCONNECTAuthorityTargetFromURL(t *testing.T) {
	t.Parallel()
	r, _ := http.NewRequest(http.MethodConnect, "https://163.5.180.181:5201/", nil)
	r.Host = "masque.local:4438"
	host, port, err := ParseCONNECTAuthorityTarget(r)
	if err != nil {
		t.Fatal(err)
	}
	if host != "163.5.180.181" || port != "5201" {
		t.Fatalf("got host=%q port=%q", host, port)
	}
}

func TestParseCONNECTAuthorityTargetFromHost(t *testing.T) {
	t.Parallel()
	r, _ := http.NewRequest(http.MethodConnect, "/", nil)
	r.Host = "example.com:8443"
	r.URL = &url.URL{Scheme: "https", Host: "example.com:8443", Path: "/"}
	host, port, err := ParseCONNECTAuthorityTarget(r)
	if err != nil {
		t.Fatal(err)
	}
	if host != "example.com" || port != "8443" {
		t.Fatalf("got host=%q port=%q", host, port)
	}
}
