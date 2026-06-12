package session

import (
	"context"
	"crypto/tls"
	"log"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/sagernet/sing-box/option"
)

// OpenH3ClientConn dials or reuses the HTTP/3 client stack for CONNECT-IP overlay.
func OpenH3ClientConn(ctx context.Context, s *CoreSession) (*http3.ClientConn, error) {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, context.Cause(ctx)
	}
	if s.IPHTTPConn != nil {
		return s.IPHTTPConn, nil
	}
	port := int(s.Options.ServerPort)
	if port <= 0 {
		port = 443
	}
	target := MasqueDialTarget(QuicDialCandidateHost(s.Options), port)
	tlsConf := ClientTLSConfig(s.Options)
	quicCfgBase := QUICConfigForDial(s.Options)
	quicDial := QuicDialWithPolicy("client_connect_ip", s.Options.QUICDial)
	transport := &http3.Transport{
		EnableDatagrams:    true,
		DisableCompression: true, // CONNECT-UDP/IP/stream are not gzip HTTP bodies
		TLSClientConfig:    tlsConf,
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, _ *quic.Config) (*quic.Conn, error) {
			cfg := ApplyQUICExperimentalOptions(quicCfgBase, s.Options.QUICExperimental)
			return quicDial(ctx, addr, tlsCfg, cfg)
		},
	}
	ApplyWarpHTTP3TransportFields(transport, s.Options)
	conn, err := transport.Dial(ctx, target, tlsConf, ApplyQUICExperimentalOptions(
		quicCfgBase,
		s.Options.QUICExperimental,
	))
	if err != nil {
		log.Printf("masque openHTTP3ClientConn failed target=%s sni=%s err=%v", target, tlsConf.ServerName, err)
		return nil, err
	}
	s.IPHTTP = transport
	s.IPHTTPConn = transport.NewClientConn(conn)
	return s.IPHTTPConn, nil
}

// ResetIPH3TransportLockedAssumeMu closes CONNECT-IP HTTP/3 transport and cached client conn.
// Caller must hold s.Mu.
func ResetIPH3TransportLockedAssumeMu(s *CoreSession) {
	if s.IPHTTP != nil {
		s.IPHTTP.Close()
		if s.TCPHTTP == s.IPHTTP {
			s.TCPHTTP = nil
		}
		s.IPHTTP = nil
	}
	s.IPHTTPConn = nil
}

// ResetTCPHTTPTransport rebuilds the CONNECT-stream HTTP overlay transport (H3 or H2 pool).
func ResetTCPHTTPTransport(s *CoreSession, host TCPHTTPTransportHost) {
	if CurrentUDPHTTPLayer(s) == option.MasqueHTTPLayerH2 {
		host.ResetH2ConnectStreamTransportLockedAssumeMu()
		return
	}
	s.Mu.Lock()
	defer s.Mu.Unlock()
	if s.TCPHTTP != nil {
		if s.TCPHTTP == s.IPHTTP {
			s.IPHTTP = nil
			s.IPHTTPConn = nil
		}
		s.TCPHTTP.Close()
	}
	tcpTLS := ClientTLSConfig(s.Options)
	quicCfgBase := TCPConnectStreamQUICConfig(s.Options)
	quicDial := QuicDialWithPolicy("client_connect_stream", s.Options.QUICDial)
	s.TCPHTTP = &http3.Transport{
		EnableDatagrams:    TCPConnectStreamHTTP3EnableDatagrams(s.Options),
		DisableCompression: true,
		TLSClientConfig:    tcpTLS,
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, _ *quic.Config) (*quic.Conn, error) {
			port := int(s.Options.ServerPort)
			if port <= 0 {
				port = 443
			}
			target := MasqueDialTarget(QuicDialCandidateHost(s.Options), port)
			cfg := ApplyQUICExperimentalOptions(quicCfgBase, s.Options.QUICExperimental)
			return quicDial(ctx, target, tlsCfg, cfg)
		},
	}
	ApplyWarpHTTP3TransportFields(s.TCPHTTP, s.Options)
}
