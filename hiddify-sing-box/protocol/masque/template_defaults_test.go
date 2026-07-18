package masque

import (
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestDefaultMasqueListenHTTPSAuthority(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		o      option.MasqueEndpointOptions
		want   string
	}{
		{"wildcard", option.MasqueEndpointOptions{Listen: "0.0.0.0", ListenPort: 8443}, "127.0.0.1:8443"},
		{"v6unspec", option.MasqueEndpointOptions{Listen: "::", ListenPort: 443}, "127.0.0.1:443"},
		{"empty", option.MasqueEndpointOptions{Listen: "", ListenPort: 443}, "127.0.0.1:443"},
		{"ip", option.MasqueEndpointOptions{Listen: "192.0.2.10", ListenPort: 8443}, "192.0.2.10:8443"},
		{"hostname", option.MasqueEndpointOptions{Listen: "vpn.example", ListenPort: 443}, "vpn.example:443"},
		{"v6", option.MasqueEndpointOptions{Listen: "2001:db8::1", ListenPort: 443}, "[2001:db8::1]:443"},
		{
			"wildcard+sni",
			option.MasqueEndpointOptions{
				Listen:     "0.0.0.0",
				ListenPort: 8443,
				InboundTLS: &option.InboundTLSOptions{ServerName: "masque.example"},
			},
			"masque.example:8443",
		},
		{
			"empty+sni",
			option.MasqueEndpointOptions{
				ListenPort: 443,
				InboundTLS: &option.InboundTLSOptions{ServerName: "proxy.example"},
			},
			"proxy.example:443",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := defaultMasqueListenHTTPSAuthority(tc.o); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
	if got := defaultMasqueListenHTTPSAuthority(option.MasqueEndpointOptions{Listen: "127.0.0.1", ListenPort: 0}); got != "127.0.0.1:443" {
		t.Fatalf("zero port: got %q", got)
	}
}

func TestMasqueTemplateNeedsAuthorityRewrite(t *testing.T) {
	t.Parallel()
	if !masqueTemplateNeedsAuthorityRewrite(option.MasqueEndpointOptions{Listen: "0.0.0.0"}) {
		t.Fatal("wildcard without SNI should need rewrite")
	}
	if masqueTemplateNeedsAuthorityRewrite(option.MasqueEndpointOptions{
		Listen:     "0.0.0.0",
		InboundTLS: &option.InboundTLSOptions{ServerName: "masque.example"},
	}) {
		t.Fatal("wildcard with SNI should not need rewrite")
	}
	if masqueTemplateNeedsAuthorityRewrite(option.MasqueEndpointOptions{Listen: "vpn.example"}) {
		t.Fatal("hostname listen should not need rewrite")
	}
}

func TestResolveMasqueServerTemplateURLsPathOnly(t *testing.T) {
	t.Parallel()
	o := option.MasqueEndpointOptions{
		Listen:     "127.0.0.1",
		ListenPort: 8443,
		PathIP:     "/masque/ip",
	}
	udp, ip, tcp := resolveMasqueServerTemplateURLs(o)
	if want := "https://127.0.0.1:8443/.well-known/masque/udp/{target_host}/{target_port}/"; udp != want {
		t.Fatalf("udp: got %q want %q", udp, want)
	}
	if want := "https://127.0.0.1:8443/masque/ip"; ip != want {
		t.Fatalf("ip: got %q want %q", ip, want)
	}
	if want := "https://127.0.0.1:8443/.well-known/masque/tcp/{target_host}/{target_port}/"; tcp != want {
		t.Fatalf("tcp: got %q want %q", tcp, want)
	}
}

func TestResolveMasqueServerTemplateURLsPreferTLSServerName(t *testing.T) {
	t.Parallel()
	o := option.MasqueEndpointOptions{
		Listen:     "0.0.0.0",
		ListenPort: 8443,
		InboundTLS: &option.InboundTLSOptions{ServerName: "masque.example"},
	}
	udp, _, _ := resolveMasqueServerTemplateURLs(o)
	if want := "https://masque.example:8443/.well-known/masque/udp/{target_host}/{target_port}/"; udp != want {
		t.Fatalf("udp: got %q want %q", udp, want)
	}
}
