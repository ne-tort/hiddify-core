package server

import (
	"crypto/tls"
	"encoding/json"
	"os"
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

func TestPrepareInboundTLS_quicOnlyH3ALPN(t *testing.T) {
	t.Parallel()
	base := &option.InboundTLSOptions{
		CertificatePath: "/tmp/cert.pem",
		KeyPath:         "/tmp/key.pem",
	}
	out, err := PrepareInboundTLS(base, option.MasqueHTTPLayerH2, true)
	if err != nil {
		t.Fatal(err)
	}
	got := inboundALPNAsSlice(t, out)
	want := []string{"h3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("quicOnly alpn %#v want %#v", got, want)
	}
}

func TestPrepareInboundTLS_explicitALPNPreserved(t *testing.T) {
	t.Parallel()
	base := &option.InboundTLSOptions{
		CertificatePath: "/tmp/cert.pem",
		KeyPath:         "/tmp/key.pem",
	}
	base.ALPN = []string{"h3", "custom"}
	out, err := PrepareInboundTLS(base, option.MasqueHTTPLayerH2, false)
	if err != nil {
		t.Fatal(err)
	}
	got := inboundALPNAsSlice(t, out)
	want := []string{"h3", "custom"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("explicit alpn should not be overwritten; got %#v want %#v", got, want)
	}
}

func TestAuthorityUseStdTLS_env(t *testing.T) {
	t.Setenv("MASQUE_SERVER_STD_TLS", "")
	if !AuthorityUseStdTLS() {
		t.Fatal("default should be std tls")
	}
	t.Setenv("MASQUE_SERVER_STD_TLS", "0")
	if AuthorityUseStdTLS() {
		t.Fatal("MASQUE_SERVER_STD_TLS=0 should use btls")
	}
}

func TestLoadAuthorityStdTLS_requiresPaths(t *testing.T) {
	t.Parallel()
	_, err := LoadAuthorityStdTLS(&option.InboundTLSOptions{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestLoadAuthorityStdTLS_fromBenchStylePEM(t *testing.T) {
	const cert = "../../../../docker/masque-vps-bench/authority-cert.pem"
	const key = "../../../../docker/masque-vps-bench/authority-key.pem"
	if _, err := os.Stat(cert); err != nil {
		t.Skip("bench PEM not in tree")
	}
	cfg, err := LoadAuthorityStdTLS(&option.InboundTLSOptions{
		CertificatePath: cert,
		KeyPath:         key,
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("min version %x", cfg.MinVersion)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("certs %d", len(cfg.Certificates))
	}
}
