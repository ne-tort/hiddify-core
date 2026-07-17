package pathbuild

import (
	"strings"
	"testing"

	"github.com/yosida95/uritemplate/v3"
)

func TestSealOpenHostPortRoundTrip(t *testing.T) {
	key := ActiveKey(true)
	opaque, err := SealHostPort(key, "2001:db8::1", 443)
	if err != nil {
		t.Fatal(err)
	}
	host, port, err := OpenHostPort(key, opaque)
	if err != nil {
		t.Fatal(err)
	}
	if host != "2001:db8::1" || port != 443 {
		t.Fatalf("got %q %d", host, port)
	}
	_, _, err = OpenHostPort(key, opaque+"x")
	if err == nil {
		t.Fatal("expected decrypt failure")
	}
}

func TestActiveKeyNilWhenDisabled(t *testing.T) {
	if ActiveKey(false) != nil {
		t.Fatal("expected nil")
	}
	if len(ActiveKey(true)) != opaqueKeySize {
		t.Fatal("expected 32-byte key")
	}
}

func TestValidatePathPrefix(t *testing.T) {
	if err := ValidatePathPrefix("/api/tunnel"); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePathPrefix("/bad/{x}"); err == nil {
		t.Fatal("expected error")
	}
	if err := ValidatePathPrefix("no-slash"); err == nil {
		t.Fatal("expected error")
	}
}

func TestFullURITemplateWellKnown(t *testing.T) {
	cfg := Config{}
	u, err := FullURITemplate("edge.example:443", PlaneTCP, cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	want := "https://edge.example:443/.well-known/masque/tcp/{target_host}/{target_port}/"
	if u != want {
		t.Fatalf("got %q want %q", u, want)
	}
	cfg = ConfigFromOptions("", "", "", true)
	u, err = FullURITemplate("edge.example:443", PlaneTCP, cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	want = "https://edge.example:443/.well-known/masque/tcp/{opaque}/"
	if u != want {
		t.Fatalf("got %q want %q", u, want)
	}
	u, err = FullURITemplate("edge.example:443", PlaneUDP, cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	want = "https://edge.example:443/.well-known/masque/udp/{opaque}/"
	if u != want {
		t.Fatalf("udp got %q want %q", u, want)
	}
	u, err = FullURITemplate("edge.example:443", PlaneIP, cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	want = "https://edge.example:443/.well-known/masque/ip/{opaque}/"
	if u != want {
		t.Fatalf("ip got %q want %q", u, want)
	}
}

func TestExpandHostPortAddrAndMaterialize(t *testing.T) {
	cfg := ConfigFromOptions("", "", "", true)
	raw, err := FullURITemplate("127.0.0.1:443", PlaneUDP, cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	tpl, err := uritemplate.New(raw)
	if err != nil {
		t.Fatal(err)
	}
	expanded, err := ExpandHostPortAddr(tpl, ActiveKey(true), "192.0.2.10:8443")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(expanded, "/.well-known/masque/udp/") || strings.Contains(expanded, "192.0.2.10") {
		t.Fatalf("expected opaque udp path, got %q", expanded)
	}
	mat, _, err := MaterializeHostPortTemplate(tpl, ActiveKey(true), "192.0.2.10:8443")
	if err != nil {
		t.Fatal(err)
	}
	if len(mat.Varnames()) != 0 {
		t.Fatalf("materialized template should have no vars, got %v", mat.Varnames())
	}
}

func TestSealOpenIPScopeRoundTrip(t *testing.T) {
	key := ActiveKey(true)
	opaque, err := SealIPScope(key, "10.0.0.0/8", 6)
	if err != nil {
		t.Fatal(err)
	}
	target, ipproto, err := OpenIPScope(key, opaque)
	if err != nil {
		t.Fatal(err)
	}
	if target != "10.0.0.0/8" || ipproto != 6 {
		t.Fatalf("got %q %d", target, ipproto)
	}
}

func TestExpandIPTemplateOpaque(t *testing.T) {
	cfg := ConfigFromOptions("", "", "", true)
	raw, err := FullURITemplate("edge.example:443", PlaneIP, cfg, true)
	if err != nil {
		t.Fatal(err)
	}
	tpl, err := uritemplate.New(raw)
	if err != nil {
		t.Fatal(err)
	}
	expanded, err := ExpandIPTemplate(tpl, ActiveKey(true), "10.0.0.0/8", 17)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(expanded, "10.0.0.0") || !strings.Contains(expanded, "/.well-known/masque/ip/") {
		t.Fatalf("expected opaque ip path, got %q", expanded)
	}
	match := tpl.Match(expanded)
	opaque := match.Get("opaque").String()
	gotTarget, gotProto, err := OpenIPScope(ActiveKey(true), opaque)
	if err != nil {
		t.Fatal(err)
	}
	if gotTarget != "10.0.0.0/8" || gotProto != 17 {
		t.Fatalf("got %q %d", gotTarget, gotProto)
	}
}
