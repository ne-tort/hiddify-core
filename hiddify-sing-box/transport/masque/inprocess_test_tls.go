package masque

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"time"

	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

// connectUDPTestTLS is a shared leaf cert (localhost + 127.0.0.1) for in-process MASQUE proxy tests.
var connectUDPTestTLS *tls.Config

func init() {
	caTempl := &x509.Certificate{
		SerialNumber:          big.NewInt(2019),
		Subject:               pkix.Name{},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("inprocess_test_tls: generate CA key: " + err.Error())
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, caTempl, caTempl, &caKey.PublicKey, caKey)
	if err != nil {
		panic("inprocess_test_tls: create CA cert: " + err.Error())
	}
	ca, err := x509.ParseCertificate(caBytes)
	if err != nil {
		panic("inprocess_test_tls: parse CA: " + err.Error())
	}

	leafTempl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"localhost", "127.0.0.1"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("inprocess_test_tls: generate leaf key: " + err.Error())
	}
	leafBytes, err := x509.CreateCertificate(rand.Reader, leafTempl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		panic("inprocess_test_tls: create leaf: " + err.Error())
	}
	if _, err := x509.ParseCertificate(leafBytes); err != nil {
		panic("inprocess_test_tls: parse leaf: " + err.Error())
	}

	connectUDPTestTLS = &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{leafBytes},
			PrivateKey:  leafKey,
		}},
		NextProtos: []string{http3.NextProtoH3, http2.NextProtoTLS},
	}
}
