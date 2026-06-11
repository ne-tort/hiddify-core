package masque

import (
	"crypto/tls"
	"os"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestMasqueAuthorityUseStdTLS_env(t *testing.T) {
	t.Setenv("MASQUE_SERVER_STD_TLS", "")
	if !masqueAuthorityUseStdTLS() {
		t.Fatal("default should be std tls")
	}
	t.Setenv("MASQUE_SERVER_STD_TLS", "0")
	if masqueAuthorityUseStdTLS() {
		t.Fatal("MASQUE_SERVER_STD_TLS=0 should use btls")
	}
}

func TestLoadMasqueAuthorityStdTLS_requiresPaths(t *testing.T) {
	_, err := loadMasqueAuthorityStdTLS(&option.InboundTLSOptions{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestLoadMasqueAuthorityStdTLS_fromBenchStylePEM(t *testing.T) {
	const cert = "../../../docker/masque-vps-bench/authority-cert.pem"
	const key = "../../../docker/masque-vps-bench/authority-key.pem"
	if _, err := os.Stat(cert); err != nil {
		t.Skip("bench PEM not in tree")
	}
	cfg, err := loadMasqueAuthorityStdTLS(&option.InboundTLSOptions{
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
