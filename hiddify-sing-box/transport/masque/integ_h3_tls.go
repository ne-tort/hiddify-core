package masque

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
)

var inProcessH3TestTLSOnce sync.Once
var inProcessH3TestTLS *tls.Config

// InProcessH3TestTLS returns a shared leaf cert for cross-package in-process HTTP/3 MASQUE tests.
func InProcessH3TestTLS(tb testing.TB) *tls.Config {
	tb.Helper()
	inProcessH3TestTLSOnce.Do(func() {
		caTempl := &x509.Certificate{
			SerialNumber: big.NewInt(2019),
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			IsCA:         true,
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		}
		caKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic("InProcessH3TestTLS: CA key: " + err.Error())
		}
		caBytes, err := x509.CreateCertificate(rand.Reader, caTempl, caTempl, &caKey.PublicKey, caKey)
		if err != nil {
			panic("InProcessH3TestTLS: CA cert: " + err.Error())
		}
		ca, err := x509.ParseCertificate(caBytes)
		if err != nil {
			panic("InProcessH3TestTLS: parse CA: " + err.Error())
		}
		leafTempl := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{},
			DNSNames:     []string{"localhost", "127.0.0.1"},
			IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}
		leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic("InProcessH3TestTLS: leaf key: " + err.Error())
		}
		leafBytes, err := x509.CreateCertificate(rand.Reader, leafTempl, ca, &leafKey.PublicKey, caKey)
		if err != nil {
			panic("InProcessH3TestTLS: leaf cert: " + err.Error())
		}
		inProcessH3TestTLS = &tls.Config{
			Certificates: []tls.Certificate{{
				Certificate: [][]byte{leafBytes},
				PrivateKey:  leafKey,
			}},
			NextProtos: []string{http3.NextProtoH3},
		}
	})
	return inProcessH3TestTLS.Clone()
}
