package masque

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"strings"
	"time"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

const warpMasqueClientCertTTL = 24 * time.Hour

// ParseWarpMasqueECDSAPrivateKey parses enrolled MASQUE device key material (matches usque/config.json private_key encoding: base64(EC SEC1 DER), or PEM block).
func ParseWarpMasqueECDSAPrivateKey(raw string) (*ecdsa.PrivateKey, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	payload := strings.TrimSpace(raw)
	if blk, _ := pem.Decode([]byte(payload)); blk != nil {
		switch strings.TrimSpace(strings.ToUpper(blk.Type)) {
		case "EC PRIVATE KEY":
			key, err := x509.ParseECPrivateKey(blk.Bytes)
			if err != nil {
				return nil, E.Cause(err, "warp_masque: failed to parse PEM EC PRIVATE KEY")
			}
			return key, nil
		}
	}
	sec1DER, err := base64.StdEncoding.DecodeString(payload)
	if err != nil || len(sec1DER) == 0 {
		return nil, E.Cause(err, "warp_masque: invalid masque_ecdsa_private_key (expect base64(EC SEC1 DER) or PEM EC PRIVATE KEY)")
	}
	key, err := x509.ParseECPrivateKey(sec1DER)
	if err != nil {
		return nil, E.Cause(err, "warp_masque: failed to parse masque ECDSA key")
	}
	return key, nil
}

// ParseWarpMasquePeerPublicKey parses peers[0].public_key PEM ( PKIX ECDSA ).
func ParseWarpMasquePeerPublicKey(raw string) (*ecdsa.PublicKey, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var der []byte
	if blk, _ := pem.Decode([]byte(raw)); blk != nil {
		der = blk.Bytes
	} else if b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw)); err == nil && len(b) > 0 {
		der = b
	} else {
		return nil, E.New("warp_masque: endpoint public key: expected PEM PKIX or PKIX base64")
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, E.New("warp_masque: endpoint public key must be ECDSA")
	}
	return ecdsaPub, nil
}

// NewWarpMasqueClientTLSCertificate builds a short-lived self-signed ECDSA TLS leaf tied to enrolled key (matches usque GenerateCert semantics).
func NewWarpMasqueClientTLSCertificate(priv *ecdsa.PrivateKey) (tls.Certificate, error) {
	if priv == nil {
		return tls.Certificate{}, E.New("warp_masque: internal: nil ECDSA key for TLS cert")
	}
	// Align template with Diniboy1123/usque internal.GenerateCert: only SerialNumber/NotBefore/NotAfter set;
	// do not populate KeyUsage/ExtKeyUsage — Cloudflare MASQUE may reject non-matching extensions.
	leafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(0),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(warpMasqueClientCertTTL),
	}, &x509.Certificate{}, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{leafDER},
		PrivateKey:  priv,
	}, nil
}

// WarpMasqueTLSPackageFromProfile returns the optional WARP client TLS certificate and ECDSA peer pin
// derived from profile options and the bootstrap peer public key PEM.
func WarpMasqueTLSPackageFromProfile(options option.WarpMasqueEndpointOptions, bootstrapPeerPubPEM string) (cert tls.Certificate, pin *ecdsa.PublicKey, err error) {
	peerBlob := strings.TrimSpace(options.Profile.EndpointPublicKey)
	if peerBlob == "" {
		peerBlob = bootstrapPeerPubPEM
	}
	priv, err := ParseWarpMasqueECDSAPrivateKey(options.Profile.MasqueECDSAPrivateKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	if priv == nil {
		return tls.Certificate{}, nil, nil
	}
	cert, err = NewWarpMasqueClientTLSCertificate(priv)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	pin, err = ParseWarpMasquePeerPublicKey(peerBlob)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	if options.Profile.DisableMasquePeerPublicKeyPin {
		pin = nil
	}
	return cert, pin, nil
}
