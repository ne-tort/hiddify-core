package session

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net"
	"strings"

	"github.com/quic-go/quic-go"
	"github.com/sagernet/sing-box/option"
	h3t "github.com/sagernet/sing-box/transport/masque/h3"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

// ErrConnectAuthorityFailed marks CONNECT-by-authority dial failures.
var ErrConnectAuthorityFailed = h3t.ErrConnectAuthorityFailed

// AuthorityDialHooks wires masque-specific TLS/QUIC/logging for CONNECT-by-authority (phase F bridge).
type AuthorityDialHooks struct {
	ClientTLSConfig         func(opts ClientOptions) *tls.Config
	TCPConnectQUICConfig    func(opts ClientOptions) *quic.Config
	ResolveDestHost         func(destination M.Socksaddr) (string, error)
	QuicDialCandidate       func(opts ClientOptions) string
	DialTarget              func(host string, port int) string
	RecordH3LayerSuccess    func()
	ResetHTTPFallbackBudget func()
}

// ConnectAuthorityClient lazily builds the greenfield client (never shares tcpHTTP / streamConn).
func ConnectAuthorityClient(s *CoreSession, hooks AuthorityDialHooks) (*h3t.AuthorityClient, error) {
	s.AuthorityClientMu.Lock()
	defer s.AuthorityClientMu.Unlock()
	if s.AuthorityClient != nil {
		return s.AuthorityClient, nil
	}
	httpLayer := strings.ToLower(strings.TrimSpace(s.Options.MasqueEffectiveHTTPLayer))
	if httpLayer == option.MasqueHTTPLayerH2 {
		return nil, E.New("connect_authority requires http_layer h3")
	}
	var tlsCfg *tls.Config
	if hooks.ClientTLSConfig != nil {
		tlsCfg = hooks.ClientTLSConfig(s.Options)
	}
	var quicCfg *quic.Config
	if hooks.TCPConnectQUICConfig != nil {
		quicCfg = hooks.TCPConnectQUICConfig(s.Options)
	}
	cl, err := h3t.NewAuthorityClient(h3t.AuthorityClientConfig{
		Tag:             strings.TrimSpace(s.Options.Tag),
		Server:          strings.TrimSpace(s.Options.Server),
		ServerPort:      s.Options.ServerPort,
		TemplateConnect: s.Options.TemplateConnect,
		TLS:             tlsCfg,
		BearerToken:     strings.TrimSpace(s.Options.ServerToken),
		BasicUsername:   strings.TrimSpace(s.Options.ClientBasicUsername),
		BasicPassword:   s.Options.ClientBasicPassword,
		QUICConfig:      quicCfg,
		// Plain quic.DialAddr (no custom packetconn): h2o/OpenSSL interop and Invisv-style minimal stack.
		QUICDial: nil,
	})
	if err != nil {
		return nil, err
	}
	s.AuthorityClient = cl
	return cl, nil
}

// DialTCPConnectAuthority dials TCP via isolated CONNECT-by-authority HTTP/3 client.
func DialTCPConnectAuthority(s *CoreSession, hooks AuthorityDialHooks, ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	targetHost, err := hooks.ResolveDestHost(destination)
	if err != nil {
		return nil, err
	}
	targetPort := destination.Port
	log.Printf("masque_connect_authority_dial tag=%s target=%s:%d server=%s:%d greenfield=1 invisv_h3=1",
		strings.TrimSpace(s.Options.Tag), targetHost, targetPort,
		strings.TrimSpace(s.Options.Server), s.Options.ServerPort)
	cl, err := ConnectAuthorityClient(s, hooks)
	if err != nil {
		return nil, errors.Join(ErrConnectAuthorityFailed, err)
	}
	conn, err := cl.DialTCP(ctx, targetHost, targetPort)
	if err != nil {
		return nil, err
	}
	portNum := int(s.Options.ServerPort)
	if portNum <= 0 {
		portNum = 443
	}
	if hooks.RecordH3LayerSuccess != nil {
		hooks.RecordH3LayerSuccess()
	}
	dialAddr := ""
	if hooks.DialTarget != nil && hooks.QuicDialCandidate != nil {
		dialAddr = hooks.DialTarget(hooks.QuicDialCandidate(s.Options), portNum)
	}
	log.Printf("masque_http_layer_chosen layer=h3 tag=%s tcp_authority=1 greenfield=1 target=%s:%d dial=%s",
		strings.TrimSpace(s.Options.Tag), targetHost, targetPort, dialAddr)
	if hooks.ResetHTTPFallbackBudget != nil {
		hooks.ResetHTTPFallbackBudget()
	}
	return conn, nil
}

// CloseConnectAuthorityClient closes the isolated authority HTTP/3 client.
func CloseConnectAuthorityClient(s *CoreSession) error {
	s.AuthorityClientMu.Lock()
	cl := s.AuthorityClient
	s.AuthorityClient = nil
	s.AuthorityClientMu.Unlock()
	if cl != nil {
		return cl.Close()
	}
	return nil
}
