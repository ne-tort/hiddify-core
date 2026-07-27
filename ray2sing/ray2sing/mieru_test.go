package ray2sing

import (
	"testing"

	T "github.com/sagernet/sing-box/option"
)

func TestIsMieruSimpleStyle(t *testing.T) {
	cases := []struct {
		rest string
		want bool
	}{
		{"user:pass@1.2.3.4?port=6666&protocol=TCP", true},
		{"user:pass@1.2.3.4?port=6666&port=9998-9999&protocol=TCP&protocol=UDP", true},
		{"user:pass@1.2.3.4:8964/?transport=TCP", false}, // legacy hiddify (port in authority, no port=)
		{"CpsBCgdkZWZhdWx0ElgKBWJhb3pp", false},             // opaque-ish
	}
	for _, c := range cases {
		if got := isMieruSimpleStyle(c.rest); got != c.want {
			t.Fatalf("rest=%q got=%v want=%v", c.rest, got, c.want)
		}
	}
}

func TestMieruSchemeAcceptsSimpleOnMieruURI(t *testing.T) {
	link := "mieru://baozi:manlianpenfen@1.2.3.4?port=6666&port=9998-9999&protocol=TCP&protocol=UDP#t"
	outs, err := MieruSingboxAll(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(outs) != 2 {
		t.Fatalf("outbounds=%d want 2", len(outs))
	}
}

func TestMierusSchemeStillWorks(t *testing.T) {
	link := "mierus://baozi:manlianpenfen@1.2.3.4?port=6666&protocol=TCP#t"
	outs, err := MieruSingboxAll(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(outs) != 1 {
		t.Fatalf("outbounds=%d", len(outs))
	}
}

func TestMieruLegacyHostPort(t *testing.T) {
	link := "mieru://user:pass@1.2.3.4:8964/?transport=TCP#n1"
	outs, err := MieruSingboxAll(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(outs) != 1 {
		t.Fatalf("len=%d", len(outs))
	}
	opts, ok := outs[0].Options.(*T.MieruOutboundOptions)
	if !ok {
		t.Fatalf("options type %T", outs[0].Options)
	}
	if opts.Server != "1.2.3.4" || opts.ServerPort != 8964 || opts.Transport != "TCP" {
		t.Fatalf("got server=%s port=%d transport=%s", opts.Server, opts.ServerPort, opts.Transport)
	}
	if opts.UserName != "user" || opts.Password != "pass" {
		t.Fatalf("creds user=%q pass=%q", opts.UserName, opts.Password)
	}
}
