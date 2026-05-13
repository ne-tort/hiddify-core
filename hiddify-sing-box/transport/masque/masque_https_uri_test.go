package masque

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
	"github.com/yosida95/uritemplate/v3"
)

func TestNormalizeMasqueTCPUDPTemplateTargetHost(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"https://x/tcp/{target}/x", "https://x/tcp/{target}/x"},
		{"https://x/tcp/{target_host}/{target_port}", "https://x/tcp/{+target_host}/{target_port}"},
		{"https://x/tcp/{+target_host}/{target_port}", "https://x/tcp/{+target_host}/{target_port}"},
		{"https://x/tcp/{target_host*}", "https://x/tcp/{+target_host*}"},
		{"https://x/tcp/{target_host:20}", "https://x/tcp/{+target_host:20}"},
	}
	for _, c := range cases {
		if got := NormalizeMasqueTCPUDPTemplateTargetHost(c.in); got != c.want {
			t.Fatalf("NormalizeMasqueTCPUDPTemplateTargetHost(%q) = %q want %q", c.in, got, c.want)
		}
	}
}

func TestMasqueTCPPathIPv6ReservedExpansionNoPercentColon(t *testing.T) {
	t.Parallel()
	raw := NormalizeMasqueTCPUDPTemplateTargetHost("https://example.com:8443/s/tcp/{target_host}/{target_port}")
	tmpl, err := uritemplate.New(raw)
	if err != nil {
		t.Fatal(err)
	}
	expanded, err := tmpl.Expand(uritemplate.Values{
		"target_host": uritemplate.String("2001:67c:4e8:f002::a"),
		"target_port": uritemplate.String("443"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(expanded, "%3A") {
		t.Fatalf("IPv6 colons should not be percent-encoded in path: %s", expanded)
	}
	wantSub := "/s/tcp/2001:67c:4e8:f002::a/443"
	if !strings.Contains(expanded, wantSub) {
		t.Fatalf("expanded URL %q missing expected segment %q", expanded, wantSub)
	}
}

func TestResolveDestinationHostIPv6JoinHostPort(t *testing.T) {
	t.Parallel()
	addr := netip.MustParseAddr("2001:b28:f23d:f001::a")
	sa := M.Socksaddr{Addr: addr, Port: 443}
	h, err := resolveDestinationHost(sa)
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(h, "[]") {
		t.Fatalf("host must be unbracketed for MASQUE path and net.JoinHostPort: %q", h)
	}
	dial := net.JoinHostPort(h, "443")
	want := "[2001:b28:f23d:f001::a]:443"
	if dial != want {
		t.Fatalf("JoinHostPort got %q want %q", dial, want)
	}
}

func TestFixMasqueExpandedTCPConnectStreamURL(t *testing.T) {
	t.Parallel()
	in := "https://163.5.180.181:18621/s18621/tcp/2001%3A67c%3A4e8%3Af002%3A%3Ab/80"
	out := FixMasqueExpandedTCPConnectStreamURL(in, false)
	if strings.Contains(out, "%3A") {
		t.Fatalf("got %q", out)
	}
	if !strings.Contains(out, "2001:67c:4e8:f002::b") {
		t.Fatalf("got %q", out)
	}
}

func TestFixMasqueExpandedTCPConnectStreamURLBracketedIPv6NoPercent(t *testing.T) {
	t.Parallel()
	in := "https://163.5.180.181:18621/s18621/tcp/[2001:67c:4e8:f002::b]/80"
	out := FixMasqueExpandedTCPConnectStreamURL(in, false)
	want := "https://163.5.180.181:18621/s18621/tcp/2001:67c:4e8:f002::b/80"
	if out != want {
		t.Fatalf("got %q want %q", out, want)
	}
}

func TestFixMasqueExpandedTCPConnectStreamURLBracketedIPv6Preserve(t *testing.T) {
	t.Parallel()
	in := "https://163.5.180.181:18621/s18621/tcp/[2001:67c:4e8:f002::b]/80"
	out := FixMasqueExpandedTCPConnectStreamURL(in, true)
	want := "https://163.5.180.181:18621/s18621/tcp/[2001:67c:4e8:f002::b]/80"
	if out != want {
		t.Fatalf("got %q want %q", out, want)
	}
}

func TestMasqueTCPPathHostForTemplateBracketIPv6(t *testing.T) {
	t.Parallel()
	h := MasqueTCPPathHostForTemplate("2001:67c:4e8:f002::a", true)
	if h != "[2001:67c:4e8:f002::a]" {
		t.Fatalf("got %q", h)
	}
	if MasqueTCPPathHostForTemplate("2001:67c:4e8:f002::a", false) != "2001:67c:4e8:f002::a" {
		t.Fatal("literal mode should not bracket")
	}
	if MasqueTCPPathHostForTemplate("example.com", true) != "example.com" {
		t.Fatal("hostname unchanged")
	}
}

func TestMasqueTCPConnectStreamRequestURLPreservesLiteralBrackets(t *testing.T) {
	t.Parallel()
	u, err := url.Parse("https://163.5.180.181:18617/s18617/tcp/[2a0a:f280:203:a:5000::100]/80")
	if err != nil {
		t.Fatal(err)
	}
	wire := MasqueTCPConnectStreamRequestURL(u)
	if strings.Contains(wire, "%5B") || strings.Contains(wire, "%5D") {
		t.Fatalf("wire URL must not encode brackets: %q", wire)
	}
	if !strings.Contains(wire, "/tcp/[2a0a:f280:203:a:5000::100]/80") {
		t.Fatalf("got %q", wire)
	}
	u2, err := url.Parse("https://163.5.180.181:18617/s18617/tcp/2001:db8::1/443")
	if err != nil {
		t.Fatal(err)
	}
	if MasqueTCPConnectStreamRequestURL(u2) != u2.String() {
		t.Fatalf("unbracketed path: got %q want %q", MasqueTCPConnectStreamRequestURL(u2), u2.String())
	}
}

func TestMasqueTCPBracketRetryEligible(t *testing.T) {
	t.Parallel()
	if !MasqueTCPBracketRetryEligible("2001:db8::1") {
		t.Fatal("v6 literal should be eligible")
	}
	if MasqueTCPBracketRetryEligible("192.0.2.1") {
		t.Fatal("v4 not eligible")
	}
	if MasqueTCPBracketRetryEligible("example.com") {
		t.Fatal("hostname not eligible")
	}
}

func TestIsMasqueTCPConnectStreamHTTP400(t *testing.T) {
	t.Parallel()
	err := fmt.Errorf("%w: status=400 url=x", ErrTCPConnectStreamFailed)
	if !isMasqueTCPConnectStreamHTTP400(err) {
		t.Fatal("expected 400")
	}
	if isMasqueTCPConnectStreamHTTP400(fmt.Errorf("%w: status=403 url=x", ErrTCPConnectStreamFailed)) {
		t.Fatal("403 not 400")
	}
	if isMasqueTCPConnectStreamHTTP400(errors.New("status=400")) {
		t.Fatal("missing ErrTCPConnectStreamFailed")
	}
}

func TestRewriteMasqueTCPURLIfPercentEncodedIPv6(t *testing.T) {
	t.Parallel()
	u, err := url.Parse("https://163.5.180.181:18615/s18615/tcp/2001%3A67c%3A4e8%3Af002%3A%3Aa/443")
	if err != nil {
		t.Fatal(err)
	}
	RewriteMasqueTCPURLIfPercentEncodedIPv6(u, false)
	if strings.Contains(u.String(), "%3A") {
		t.Fatalf("expected literal IPv6 in URL, got %q", u.String())
	}
	if !strings.Contains(u.Path, "2001:67c:4e8:f002::a") {
		t.Fatalf("decoded IPv6 missing in path: %q", u.Path)
	}
}

func TestRewriteMasqueTCPURLIfPercentEncodedIPv6BracketMode(t *testing.T) {
	t.Parallel()
	u, err := url.Parse("https://163.5.180.181:18615/s18615/tcp/2001%3A67c%3A4e8%3Af002%3A%3Aa/443")
	if err != nil {
		t.Fatal(err)
	}
	RewriteMasqueTCPURLIfPercentEncodedIPv6(u, true)
	if !strings.Contains(u.Path, "[2001:67c:4e8:f002::a]") {
		t.Fatalf("want bracketed IPv6 in path, got %q", u.Path)
	}
}

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
