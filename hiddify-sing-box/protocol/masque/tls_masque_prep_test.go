package masque

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func inboundALPNAsSlice(t *testing.T, in *option.InboundTLSOptions) []string {
	t.Helper()
	if in == nil {
		return nil
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal inbound tls: %v", err)
	}
	var raw struct {
		ALPN []string `json:"alpn"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("unmarshal alpn: %v", err)
	}
	return raw.ALPN
}

func TestPrepareMasqueServerInboundTLS_nilRejected(t *testing.T) {
	_, err := prepareMasqueServerInboundTLS(nil, option.MasqueHTTPLayerH3)
	if err == nil {
		t.Fatal("expected error for nil tls")
	}
}

func TestPrepareMasqueServerInboundTLS_defaultALPNForH3AndAuto(t *testing.T) {
	base := &option.InboundTLSOptions{
		CertificatePath: "/tmp/cert.pem",
		KeyPath:         "/tmp/key.pem",
	}
	for _, hint := range []string{"", option.MasqueHTTPLayerH3, option.MasqueHTTPLayerAuto} {
		t.Run("hint_"+hint, func(t *testing.T) {
			out, err := prepareMasqueServerInboundTLS(base, hint)
			if err != nil {
				t.Fatal(err)
			}
			if !out.Enabled {
				t.Fatal("expected Enabled true")
			}
			got := inboundALPNAsSlice(t, out)
			want := []string{"h3", "h2", "http/1.1"}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("hint %q: alpn %#v want %#v", hint, got, want)
			}
		})
	}
}

func TestPrepareMasqueServerInboundTLS_h2DefaultALPN(t *testing.T) {
	base := &option.InboundTLSOptions{
		CertificatePath: "/tmp/cert.pem",
		KeyPath:         "/tmp/key.pem",
	}
	out, err := prepareMasqueServerInboundTLS(base, option.MasqueHTTPLayerH2)
	if err != nil {
		t.Fatal(err)
	}
	got := inboundALPNAsSlice(t, out)
	want := []string{"h2", "http/1.1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("alpn %#v want %#v", got, want)
	}
}

func TestPrepareMasqueServerInboundTLS_explicitALPNPreserved(t *testing.T) {
	base := &option.InboundTLSOptions{
		CertificatePath: "/tmp/cert.pem",
		KeyPath:         "/tmp/key.pem",
	}
	base.ALPN = []string{"h3", "custom"}
	out, err := prepareMasqueServerInboundTLS(base, option.MasqueHTTPLayerH2)
	if err != nil {
		t.Fatal(err)
	}
	got := inboundALPNAsSlice(t, out)
	want := []string{"h3", "custom"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("explicit alpn should not be overwritten; got %#v want %#v", got, want)
	}
}
