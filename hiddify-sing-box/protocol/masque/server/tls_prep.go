package server

import (
	"crypto/tls"
	"os"
	"strings"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// PrepareInboundTLS returns a copy of inbound TLS with Enabled set and ALPN defaults for QUIC vs TCP listeners.
// quicOnly matches masque-thin-server (ALPN h3 only) for authority-only HTTP/3 sidecars.
func PrepareInboundTLS(in *option.InboundTLSOptions, httpLayerHint string, quicOnly bool) (*option.InboundTLSOptions, error) {
	if in == nil {
		return nil, E.New("masque server: tls is required")
	}
	out := *in
	out.Enabled = true
	if quicOnly {
		if len(out.ALPN) == 0 {
			out.ALPN = []string{"h3"}
		}
		return &out, nil
	}
	layer := strings.ToLower(strings.TrimSpace(httpLayerHint))
	if layer == "" {
		layer = option.MasqueHTTPLayerH3
	}
	if len(out.ALPN) == 0 {
		switch layer {
		case option.MasqueHTTPLayerH2:
			out.ALPN = []string{"h2", "http/1.1"}
		case option.MasqueHTTPLayerH3, option.MasqueHTTPLayerAuto:
			fallthrough
		default:
			// MASQUE server listens QUIC/H3 and TCP/H2 on the same port; defaults must advertise
			// both so the TCP listener can negotiate h2 after TLS clone.
			out.ALPN = []string{"h3", "h2", "http/1.1"}
		}
	}
	return &out, nil
}

// AuthorityUseStdTLS selects crypto/tls.LoadX509KeyPair + http3.ConfigureTLSConfig (masque-thin-server parity).
// Default on for authority minimal; MASQUE_SERVER_STD_TLS=0 keeps sing-box btls inbound.
func AuthorityUseStdTLS() bool {
	switch strings.TrimSpace(strings.ToLower(os.Getenv("MASQUE_SERVER_STD_TLS"))) {
	case "0", "false", "btls", "no", "off":
		return false
	case "1", "true", "std", "yes", "on":
		return true
	default:
		return true
	}
}

// LoadAuthorityStdTLS loads PEM cert/key like masque-thin-server (no btls.ServerConfig lifecycle).
func LoadAuthorityStdTLS(in *option.InboundTLSOptions) (*tls.Config, error) {
	if in == nil {
		return nil, E.New("masque server: tls is required")
	}
	certPath := strings.TrimSpace(in.CertificatePath)
	keyPath := strings.TrimSpace(in.KeyPath)
	if certPath == "" || keyPath == "" {
		return nil, E.New("masque authority std tls: certificate_path and key_path are required")
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, E.Cause(err, "masque authority std tls load cert")
	}
	minVer := uint16(tls.VersionTLS13)
	if v := strings.TrimSpace(in.MinVersion); v != "" {
		switch strings.ToLower(v) {
		case "1.2", "tls1.2", "tls 1.2":
			minVer = tls.VersionTLS12
		case "1.3", "tls1.3", "tls 1.3":
			minVer = tls.VersionTLS13
		}
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   minVer,
	}, nil
}
