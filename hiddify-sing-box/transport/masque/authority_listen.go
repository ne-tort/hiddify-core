package masque

import (
	"crypto/tls"
	"net"
	"net/http"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// AuthorityListenOptions configures a thin-parity HTTP/3 CONNECT authority listener.
type AuthorityListenOptions struct {
	ListenAddr      string
	TLSConfig       *tls.Config // already passed through http3.ConfigureTLSConfig, or raw for helper to configure
	Handler         http.Handler
	QUICConfig      *quic.Config
	EnableDatagrams bool
}

// AuthorityHTTPServer is a minimal HTTP/3 server (masque-thin-server parity).
type AuthorityHTTPServer struct {
	Server     *http3.Server
	PacketConn net.PacketConn
}

// StartAuthorityHTTPServer listens UDP and serves HTTP/3 like masque-thin-server.
func StartAuthorityHTTPServer(opts AuthorityListenOptions) (*AuthorityHTTPServer, error) {
	pc, err := net.ListenPacket("udp", opts.ListenAddr)
	if err != nil {
		return nil, err
	}
	tlsCfg := opts.TLSConfig
	if tlsCfg != nil && len(tlsCfg.NextProtos) == 0 {
		tlsCfg = http3.ConfigureTLSConfig(tlsCfg)
	}
	quicCfg := opts.QUICConfig
	if quicCfg == nil {
		quicCfg = MasqueAuthorityHTTPServerQUICConfig()
	}
	srv := &http3.Server{
		Handler:         opts.Handler,
		TLSConfig:       tlsCfg,
		EnableDatagrams: opts.EnableDatagrams,
		QUICConfig:      quicCfg,
	}
	return &AuthorityHTTPServer{Server: srv, PacketConn: pc}, nil
}

// Serve blocks until the server stops (call from a goroutine).
func (a *AuthorityHTTPServer) Serve() error {
	if a == nil || a.Server == nil || a.PacketConn == nil {
		return nil
	}
	return a.Server.Serve(a.PacketConn)
}

// Close shuts down the HTTP/3 server and UDP socket.
func (a *AuthorityHTTPServer) Close() error {
	if a == nil {
		return nil
	}
	var err error
	if a.Server != nil {
		err = a.Server.Close()
	}
	if a.PacketConn != nil {
		if closeErr := a.PacketConn.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}
	return err
}

// LoadAuthorityTLSFromPEM loads server TLS like masque-thin-server and returns http3-ready config.
func LoadAuthorityTLSFromPEM(certPath, keyPath string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	return http3.ConfigureTLSConfig(&tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}), nil
}
