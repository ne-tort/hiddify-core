package session

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"github.com/quic-go/quic-go/http3"
	h3t "github.com/sagernet/sing-box/transport/masque/h3"
)

// ClientTLSConfig returns TLS settings for MASQUE QUIC/HTTP3 client dial.
func ClientTLSConfig(opts ClientOptions) *tls.Config {
	if len(opts.WarpMasqueClientCert.Certificate) > 0 {
		return clientTLSConfigWarp(opts)
	}
	if opts.MasqueQUICCryptoTLS != nil {
		cfg := opts.MasqueQUICCryptoTLS.Clone()
		if len(cfg.NextProtos) == 0 {
			cfg.NextProtos = []string{http3.NextProtoH3}
		}
		return cfg
	}
	return &tls.Config{
		NextProtos: []string{http3.NextProtoH3},
		ServerName: ResolveTLSServerName(opts),
	}
}

func clientTLSConfigWarp(opts ClientOptions) *tls.Config {
	cfg := &tls.Config{
		NextProtos: []string{http3.NextProtoH3},
		ServerName: ResolveTLSServerName(opts),
	}
	cfg.Certificates = []tls.Certificate{opts.WarpMasqueClientCert}
	cfg.InsecureSkipVerify = true
	insecure := opts.MasqueQUICCryptoTLS != nil && opts.MasqueQUICCryptoTLS.InsecureSkipVerify
	if opts.WarpMasquePinnedPubKey != nil && !insecure {
		pub := opts.WarpMasquePinnedPubKey
		cfg.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("warp_masque: empty peer TLS certificate")
			}
			leaf, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			esk, ok := leaf.PublicKey.(*ecdsa.PublicKey)
			if !ok {
				return fmt.Errorf("warp_masque: peer TLS certificate is not ECDSA")
			}
			if !esk.Equal(pub) {
				return fmt.Errorf("warp_masque: peer TLS public key does not match Cloudflare device profile pin")
			}
			return nil
		}
	}
	if insecure {
		cfg.VerifyPeerCertificate = nil
	}
	return cfg
}

// ApplyWarpHTTP3TransportFields configures WARP-specific HTTP/3 transport knobs.
func ApplyWarpHTTP3TransportFields(tr *http3.Transport, opts ClientOptions) {
	h3t.ApplyWarpTransportFields(tr, h3t.WarpTransportOptions{
		LegacyH3Extras: opts.WarpMasqueLegacyH3Extras,
		CfConnectIP:    h3t.CfConnectIPProtocol(opts.WarpConnectIPProtocol),
	})
}
