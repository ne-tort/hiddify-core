package connectudp

import (
	"testing"

	"github.com/yosida95/uritemplate/v3"
)

func TestExpandedURLAuthority(t *testing.T) {
	t.Parallel()
	raw := "https://proxy.example:8443/masque/udp/{target_host}/{target_port}"
	tpl, err := uritemplate.New(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got := ExpandedURLAuthority(tpl, "1.2.3.4:5353"); got != "proxy.example:8443" {
		t.Fatalf("authority: got %q", got)
	}
	if ExpandedURLAuthority(nil, "1.2.3.4:53") != "" {
		t.Fatal("nil template expected empty authority")
	}
	if ExpandedURLAuthority(tpl, "nohostport") != "" {
		t.Fatal("bad target expected empty authority")
	}
}

func TestConnectObservabilityFields(t *testing.T) {
	t.Parallel()
	raw := "https://proxy.example:8443/masque/udp/{target_host}/{target_port}"
	tpl, err := uritemplate.New(raw)
	if err != nil {
		t.Fatal(err)
	}
	wantDial := "edge.example:443"
	lt, dial := ConnectObservabilityFields(ObservabilityInput{
		Template: tpl,
		Target:   "1.2.3.4:5353",
		ResolveDialAddr: func() string {
			return wantDial
		},
	})
	if lt != "proxy.example:8443" {
		t.Fatalf("target: got %q", lt)
	}
	if dial != wantDial {
		t.Fatalf("dial: got %q want %q", dial, wantDial)
	}
	_, dial0 := ConnectObservabilityFields(ObservabilityInput{
		Template: tpl,
		Target:   "8.8.8.8:53",
		ResolveDialAddr: func() string {
			return "srv.example:443"
		},
	})
	if dial0 != "srv.example:443" {
		t.Fatalf("resolver dial mismatch: got %q", dial0)
	}
}
