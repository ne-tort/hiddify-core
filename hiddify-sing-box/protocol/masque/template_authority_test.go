package masque

import (
	"net/http"
	"testing"

	cudpframe "github.com/sagernet/sing-box/transport/masque/connectudp/frame"
	"github.com/sagernet/sing-box/option"
	"github.com/yosida95/uritemplate/v3"
)

func TestMasqueServerShouldRelaxTemplateAuthority(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		opts   option.MasqueEndpointOptions
		field  string
		relax  bool
	}{
		{"udp wildcard empty template", option.MasqueEndpointOptions{Listen: "::", ListenPort: 8443}, masqueTemplateFieldUDP, true},
		{"udp 0.0.0.0", option.MasqueEndpointOptions{Listen: "0.0.0.0"}, masqueTemplateFieldUDP, true},
		{"udp empty listen", option.MasqueEndpointOptions{Listen: ""}, masqueTemplateFieldUDP, true},
		{"udp explicit template", option.MasqueEndpointOptions{Listen: "::", TemplateUDP: "https://x/x"}, masqueTemplateFieldUDP, false},
		{"udp specific listen", option.MasqueEndpointOptions{Listen: "192.0.2.1"}, masqueTemplateFieldUDP, false},
		{"ip wildcard", option.MasqueEndpointOptions{Listen: "0.0.0.0"}, masqueTemplateFieldIP, true},
		{"ip explicit template", option.MasqueEndpointOptions{Listen: "::", TemplateIP: "https://x/x"}, masqueTemplateFieldIP, false},
		{"tcp wildcard", option.MasqueEndpointOptions{Listen: "::"}, masqueTemplateFieldTCP, true},
		{"tcp explicit template", option.MasqueEndpointOptions{Listen: "", TemplateTCP: "https://x/x"}, masqueTemplateFieldTCP, false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := masqueServerShouldRelaxTemplateAuthority(tc.opts, tc.field)
			if got != tc.relax {
				t.Fatalf("relax=%v want %v opts=%+v field=%s", got, tc.relax, tc.opts, tc.field)
			}
		})
	}
}

func TestMasqueRequestAuthorityMatchesTemplate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		template string
		request  string
		relax    bool
		want     bool
	}{
		{"exact", "127.0.0.1:4438", "127.0.0.1:4438", false, true},
		{"public vs loopback relaxed", "127.0.0.1:4438", "193.233.216.26:4438", true, true},
		{"port mismatch", "127.0.0.1:4438", "193.233.216.26:8443", true, false},
		{"public host without port", "127.0.0.1:4433", "163.5.180.181", true, true},
		{"no relax mismatch", "127.0.0.1:4438", "193.233.216.26:4438", false, false},
		{"non-loopback template", "203.0.113.1:4438", "193.233.216.26:4438", true, false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := masqueRequestAuthorityMatchesTemplate(tc.template, tc.request, tc.relax)
			if got != tc.want {
				t.Fatalf("match=%v want %v template=%q request=%q relax=%v", got, tc.want, tc.template, tc.request, tc.relax)
			}
		})
	}
}

func TestMasqueHTTPRequestForTemplateParseUDP(t *testing.T) {
	t.Parallel()
	template := uritemplate.MustNew("https://127.0.0.1:4438/masque/udp/{target_host}/{target_port}")
	req, err := http.NewRequest(http.MethodConnect, "https://127.0.0.1:4438/masque/udp/example.com/53", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "193.233.216.26:4438"
	parseR := masqueHTTPRequestForTemplateParse(req, template, true)
	if parseR.Host != "127.0.0.1:4438" {
		t.Fatalf("relaxed host: got %q want 127.0.0.1:4438", parseR.Host)
	}
}

func TestMasqueHTTPRequestForTemplateParseExplicitHostWithoutPort(t *testing.T) {
	t.Parallel()
	template := uritemplate.MustNew("https://163.5.180.181:4433/masque/udp/{+target_host}/{target_port}")
	req, err := http.NewRequest(http.MethodConnect, "https://163.5.180.181:4433/masque/udp/8.8.8.8/53", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "163.5.180.181"
	parseR := masqueHTTPRequestForTemplateParse(req, template, false)
	if parseR.Host != "163.5.180.181:4433" {
		t.Fatalf("normalized host: got %q want 163.5.180.181:4433", parseR.Host)
	}
	if parseR.URL == nil || parseR.URL.Host != "163.5.180.181:4433" {
		t.Fatalf("normalized URL host: got %v", parseR.URL)
	}
}

func TestMasqueHTTPRequestForTemplateParseLoopbackRewritesURLHost(t *testing.T) {
	t.Parallel()
	template := uritemplate.MustNew("https://127.0.0.1:4433/masque/udp/{+target_host}/{target_port}")
	req, err := http.NewRequest(http.MethodConnect, "https://163.5.180.181:4433/masque/udp/8.8.8.8/53", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "163.5.180.181:4433"
	parseR := masqueHTTPRequestForTemplateParse(req, template, true)
	if parseR.Host != "127.0.0.1:4433" {
		t.Fatalf("relaxed host: got %q want 127.0.0.1:4433", parseR.Host)
	}
	if parseR.URL == nil || parseR.URL.Host != "127.0.0.1:4433" {
		t.Fatalf("relaxed URL host: got %v", parseR.URL)
	}
}

func TestMasqueHTTPRequestForTemplateParseLoopbackConnectUDPParse(t *testing.T) {
	t.Parallel()
	template := uritemplate.MustNew("https://127.0.0.1:4433/masque/udp/{+target_host}/{target_port}")
	req, err := http.NewRequest(http.MethodConnect, "https://163.5.180.181:4433/masque/udp/8.8.8.8/53", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "163.5.180.181:4433"
	req.Proto = cudpframe.RequestProtocol
	parseR := masqueHTTPRequestForTemplateParse(req, template, true)
	parsed, err := cudpframe.ParseRequest(parseR, template)
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}
	if parsed.Target != "8.8.8.8:53" {
		t.Fatalf("target=%q", parsed.Target)
	}
}
