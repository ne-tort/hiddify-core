package masque

import (
	"context"
	"errors"
	"log"
	"net"
	"strings"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque/connectauthority"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

var ErrTCPConnectAuthorityFailed = connectauthority.ErrConnectAuthorityFailed

// connectAuthorityClient lazily builds the greenfield client (never shares tcpHTTP / streamConn).
func (s *coreSession) connectAuthorityClient() (*connectauthority.Client, error) {
	s.authorityClientMu.Lock()
	defer s.authorityClientMu.Unlock()
	if s.authorityClient != nil {
		return s.authorityClient, nil
	}
	httpLayer := strings.ToLower(strings.TrimSpace(s.options.MasqueEffectiveHTTPLayer))
	if httpLayer == option.MasqueHTTPLayerH2 {
		return nil, E.New("connect_authority requires http_layer h3")
	}
	port := int(s.options.ServerPort)
	if port <= 0 {
		port = 443
	}
	cl, err := connectauthority.NewClient(connectauthority.ClientConfig{
		Tag:             strings.TrimSpace(s.options.Tag),
		Server:          strings.TrimSpace(s.options.Server),
		ServerPort:      s.options.ServerPort,
		TemplateConnect: s.options.TemplateConnect,
		TLS:             masqueClientTLSConfig(s.options),
		BearerToken:     strings.TrimSpace(s.options.ServerToken),
		BasicUsername:   strings.TrimSpace(s.options.ClientBasicUsername),
		BasicPassword:   s.options.ClientBasicPassword,
		QUICConfig:      masqueTCPConnectStreamQUICConfig(s.options),
		// Plain quic.DialAddr (no custom packetconn): h2o/OpenSSL interop and Invisv-style minimal stack.
		QUICDial: nil,
	})
	if err != nil {
		return nil, err
	}
	s.authorityClient = cl
	return cl, nil
}

func (s *coreSession) dialTCPConnectAuthority(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	targetHost, err := resolveDestinationHost(destination)
	if err != nil {
		return nil, err
	}
	targetPort := destination.Port
	log.Printf("masque_connect_authority_dial tag=%s target=%s:%d server=%s:%d greenfield=1 invisv_h3=1",
		strings.TrimSpace(s.options.Tag), targetHost, targetPort,
		strings.TrimSpace(s.options.Server), s.options.ServerPort)
	cl, err := s.connectAuthorityClient()
	if err != nil {
		return nil, errors.Join(ErrTCPConnectAuthorityFailed, err)
	}
	conn, err := cl.DialTCP(ctx, targetHost, targetPort)
	if err != nil {
		return nil, err
	}
	portNum := int(s.options.ServerPort)
	if portNum <= 0 {
		portNum = 443
	}
	s.maybeRecordHTTPLayerCacheSuccess(option.MasqueHTTPLayerH3)
	log.Printf("masque_http_layer_chosen layer=h3 tag=%s tcp_authority=1 greenfield=1 target=%s:%d dial=%s",
		strings.TrimSpace(s.options.Tag), targetHost, targetPort, masqueDialTarget(masqueQuicDialCandidateHost(s.options), portNum))
	s.resetHTTPFallbackBudgetAfterSuccess()
	return conn, nil
}

// closeConnectAuthorityClient closes the isolated authority HTTP/3 client.
func (s *coreSession) closeConnectAuthorityClient() error {
	s.authorityClientMu.Lock()
	cl := s.authorityClient
	s.authorityClient = nil
	s.authorityClientMu.Unlock()
	if cl != nil {
		return cl.Close()
	}
	return nil
}
