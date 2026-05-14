package masque

import (
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestDefaultMasqueListenHTTPSAuthority(t *testing.T) {
	t.Parallel()
	cases := []struct {
		listen string
		port   uint16
		want   string
	}{
		{"0.0.0.0", 8443, "127.0.0.1:8443"},
		{"::", 443, "127.0.0.1:443"},
		{"", 443, "127.0.0.1:443"},
		{"192.0.2.10", 8443, "192.0.2.10:8443"},
		{"vpn.example", 443, "vpn.example:443"},
		{"2001:db8::1", 443, "[2001:db8::1]:443"},
	}
	for _, tc := range cases {
		if got := defaultMasqueListenHTTPSAuthority(tc.listen, tc.port); got != tc.want {
			t.Fatalf("listen=%q port=%d: got %q want %q", tc.listen, tc.port, got, tc.want)
		}
	}
	if got := defaultMasqueListenHTTPSAuthority("127.0.0.1", 0); got != "127.0.0.1:443" {
		t.Fatalf("zero port: got %q", got)
	}
}

func TestResolveMasqueServerTemplateURLsPathOnly(t *testing.T) {
	t.Parallel()
	o := option.MasqueEndpointOptions{
		Listen:     "127.0.0.1",
		ListenPort: 8443,
		TemplateIP: "/masque/ip",
	}
	udp, ip, tcp := resolveMasqueServerTemplateURLs(o)
	if want := "https://127.0.0.1:8443/masque/udp/{+target_host}/{target_port}"; udp != want {
		t.Fatalf("udp: got %q want %q", udp, want)
	}
	if want := "https://127.0.0.1:8443/masque/ip"; ip != want {
		t.Fatalf("ip: got %q want %q", ip, want)
	}
	if want := "https://127.0.0.1:8443/masque/tcp/{+target_host}/{target_port}"; tcp != want {
		t.Fatalf("tcp: got %q want %q", tcp, want)
	}
}
