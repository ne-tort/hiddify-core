package masque

import (
	"net/url"
	"strings"
	"testing"
)

func TestExpandMasqueHTTPSURI(t *testing.T) {
	t.Parallel()
	if got := ExpandMasqueHTTPSURI("", "127.0.0.1:443"); got != "" {
		t.Fatalf("empty raw: got %q", got)
	}
	if got := ExpandMasqueHTTPSURI("/masque/ip", "127.0.0.1:8443"); got != "https://127.0.0.1:8443/masque/ip" {
		t.Fatalf("path-only: got %q", got)
	}
	if got := ExpandMasqueHTTPSURI("https://edge.example/masque/ip", "127.0.0.1:443"); got != "https://edge.example/masque/ip" {
		t.Fatalf("absolute: got %q", got)
	}
	if got := ExpandMasqueHTTPSURI("//edge.example/masque/ip", "127.0.0.1:443"); got != "//edge.example/masque/ip" {
		t.Fatalf("scheme-relative: got %q", got)
	}
	if got := ExpandMasqueHTTPSURI("/.well-known/masque/udp/{target_host}/{target_port}/", "[::1]:443"); got != "https://[::1]:443/.well-known/masque/udp/{target_host}/{target_port}/" {
		t.Fatalf("ipv6 authority: got %q", got)
	}
}

func TestMasqueTCPConnectStreamRequestURLKeepsLiteralBrackets(t *testing.T) {
	t.Parallel()
	u, err := url.Parse("https://edge.example/.well-known/masque/tcp/[2001:db8::1]/443/")
	if err != nil {
		t.Fatal(err)
	}
	got := MasqueTCPConnectStreamRequestURL(u)
	if !strings.Contains(got, "[2001:db8::1]") {
		t.Fatalf("expected literal brackets in %q", got)
	}
	if strings.Contains(got, "%5B") {
		t.Fatalf("unexpected percent-encoded brackets in %q", got)
	}
}
