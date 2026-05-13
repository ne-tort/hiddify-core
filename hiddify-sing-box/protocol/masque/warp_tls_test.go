package masque

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestParseWarpMasqueECDSAPrivateKey_RoundTrip(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sec1DER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	raw := base64.StdEncoding.EncodeToString(sec1DER)
	got, err := ParseWarpMasqueECDSAPrivateKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !got.PublicKey.Equal(&priv.PublicKey) {
		t.Fatal("unexpected key mismatch")
	}
	cert, err := NewWarpMasqueClientTLSCertificate(got)
	if err != nil || len(cert.Certificate) != 1 {
		t.Fatal("leaf cert generation failed")
	}
}

func TestWarpMasqueTLSPackageFromProfile_PinDisabled(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sec1DER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	opts := option.WarpMasqueEndpointOptions{
		Profile: option.WarpMasqueProfileOptions{
			MasqueECDSAPrivateKey:         base64.StdEncoding.EncodeToString(sec1DER),
			DisableMasquePeerPublicKeyPin: true,
		},
	}
	cert, pin, err := WarpMasqueTLSPackageFromProfile(opts, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.Certificate) == 0 || pin != nil {
		t.Fatalf("expected leaf cert without pin, got pin=%v", pin)
	}
}

func TestWarpMasqueTLSPackageFromProfile_NonPKIXBootstrapSkipsPin(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sec1DER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	opts := option.WarpMasqueEndpointOptions{
		Profile: option.WarpMasqueProfileOptions{
			MasqueECDSAPrivateKey: base64.StdEncoding.EncodeToString(sec1DER),
		},
	}
	// 32-byte blob (WG-style) is not PKIX ECDSA; must not fail TLS package — pin omitted.
	wgLike := base64.StdEncoding.EncodeToString(make([]byte, 32))
	cert, pin, err := WarpMasqueTLSPackageFromProfile(opts, wgLike)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.Certificate) == 0 || pin != nil {
		t.Fatalf("expected leaf cert without pin for non-PKIX bootstrap, pin=%v", pin)
	}
}
