package server

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

func TestPrepareInboundTLS_nilRejected(t *testing.T) {
	t.Parallel()
	_, err := PrepareInboundTLS(nil, option.MasqueHTTPLayerH3, false)
	if err == nil {
		t.Fatal("expected error for nil tls")
	}
}

func TestPrepareInboundTLS_defaultALPNForH3AndAuto(t *testing.T) {
	t.Parallel()
	base := &option.InboundTLSOptions{
		CertificatePath: "/tmp/cert.pem",
		KeyPath:         "/tmp/key.pem",
	}
	for _, hint := range []string{"", option.MasqueHTTPLayerH3, option.MasqueHTTPLayerAuto} {
		t.Run("hint_"+hint, func(t *testing.T) {
			out, err := PrepareInboundTLS(base, hint, false)
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

func TestPrepareInboundTLS_h2DefaultALPN(t *testing.T) {
	t.Parallel()
	base := &option.InboundTLSOptions{
		CertificatePath: "/tmp/cert.pem",
		KeyPath:         "/tmp/key.pem",
	}
	out, err := PrepareInboundTLS(base, option.MasqueHTTPLayerH2, false)
	if err != nil {
		t.Fatal(err)
	}
	got := inboundALPNAsSlice(t, out)
	want := []string{"h2", "http/1.1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("alpn %#v want %#v", got, want)
	}
}

func TestPrepareInboundTLS_explicitALPNPreserved(t *testing.T) {
	t.Parallel()
	base := &option.InboundTLSOptions{
		CertificatePath: "/tmp/cert.pem",
		KeyPath:         "/tmp/key.pem",
	}
	base.ALPN = []string{"h3", "h2", "custom"}
	out, err := PrepareInboundTLS(base, option.MasqueHTTPLayerH3, false)
	if err != nil {
		t.Fatal(err)
	}
	got := inboundALPNAsSlice(t, out)
	want := []string{"h3", "h2", "custom"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("explicit alpn should not be overwritten; got %#v want %#v", got, want)
	}
}

func TestPrepareInboundTLS_explicitALPNH2MissingRejected(t *testing.T) {
	t.Parallel()
	base := &option.InboundTLSOptions{
		CertificatePath: "/tmp/cert.pem",
		KeyPath:         "/tmp/key.pem",
		ALPN:            []string{"http/1.1"},
	}
	_, err := PrepareInboundTLS(base, option.MasqueHTTPLayerH2, false)
	if err == nil {
		t.Fatal("expected error when h2 layer alpn lacks h2")
	}
}

func TestPrepareInboundTLS_autoExplicitRequiresBoth(t *testing.T) {
	t.Parallel()
	base := &option.InboundTLSOptions{
		CertificatePath: "/tmp/cert.pem",
		KeyPath:         "/tmp/key.pem",
		ALPN:            []string{"h3"},
	}
	_, err := PrepareInboundTLS(base, option.MasqueHTTPLayerAuto, false)
	if err == nil {
		t.Fatal("expected error when auto alpn lacks h2")
	}
}

func TestPrepareInboundTLS_autoDefaultDual(t *testing.T) {
	t.Parallel()
	base := &option.InboundTLSOptions{
		CertificatePath: "/tmp/cert.pem",
		KeyPath:         "/tmp/key.pem",
	}
	out, err := PrepareInboundTLS(base, option.MasqueHTTPLayerAuto, false)
	if err != nil {
		t.Fatal(err)
	}
	got := inboundALPNAsSlice(t, out)
	want := []string{"h3", "h2", "http/1.1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("alpn %#v want %#v", got, want)
	}
}
