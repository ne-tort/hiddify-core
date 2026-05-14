package masque

import (
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestValidateMasqueClientTLSMaterial_exclusive(t *testing.T) {
	err := validateMasqueClientTLSMaterial(option.MasqueEndpointOptions{
		ClientTLSCertPEM: "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----",
		ClientTLSKeyPEM:  "-----BEGIN EC PRIVATE KEY-----\nY\n-----END EC PRIVATE KEY-----",
		ClientTLSCert:    "/a.crt",
		ClientTLSKey:     "/a.key",
	})
	if err == nil || !strings.Contains(err.Error(), "only one") {
		t.Fatalf("expected exclusive error, got %v", err)
	}
}

func TestValidateMasqueClientTLSMaterial_pemOnlyOK(t *testing.T) {
	err := validateMasqueClientTLSMaterial(option.MasqueEndpointOptions{
		ClientTLSCertPEM: "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----",
		ClientTLSKeyPEM:  "-----BEGIN EC PRIVATE KEY-----\nY\n-----END EC PRIVATE KEY-----",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestValidateMasqueClientTLSMaterial_pathPartial(t *testing.T) {
	err := validateMasqueClientTLSMaterial(option.MasqueEndpointOptions{
		ClientTLSCert: "/x",
	})
	if err == nil || !strings.Contains(err.Error(), "client_tls_cert and client_tls_key") {
		t.Fatalf("expected path pair error, got %v", err)
	}
}
