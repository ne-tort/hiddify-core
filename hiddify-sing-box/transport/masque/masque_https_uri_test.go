package masque

import "testing"

func TestExpandMasqueHTTPSURI(t *testing.T) {
	t.Parallel()
	if got := ExpandMasqueHTTPSURI("", "127.0.0.1:443"); got != "" {
		t.Fatalf("empty: got %q", got)
	}
	if got := ExpandMasqueHTTPSURI("/masque/ip", "127.0.0.1:8443"); got != "https://127.0.0.1:8443/masque/ip" {
		t.Fatalf("path: got %q", got)
	}
	if got := ExpandMasqueHTTPSURI("https://edge.example/masque/ip", "127.0.0.1:443"); got != "https://edge.example/masque/ip" {
		t.Fatalf("full url: got %q", got)
	}
	if got := ExpandMasqueHTTPSURI("//edge.example/masque/ip", "127.0.0.1:443"); got != "//edge.example/masque/ip" {
		t.Fatalf("scheme-relative: got %q", got)
	}
	if got := ExpandMasqueHTTPSURI("/masque/udp/{target_host}/{target_port}", "[::1]:443"); got != "https://[::1]:443/masque/udp/{target_host}/{target_port}" {
		t.Fatalf("ipv6 auth: got %q", got)
	}
}
