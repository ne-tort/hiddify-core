package session

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/sagernet/sing-box/option"
	h3t "github.com/sagernet/sing-box/transport/masque/h3"
)

// connectStreamQUICWarmTimeout bounds one shared CONNECT-stream QUIC handshake warm.
const connectStreamQUICWarmTimeout = 30 * time.Second

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
			conn, err := quicDial(ctx, addr, tlsCfg, cfg)
			if err != nil {
				return nil, err
			}
			h3t.ApplyExternalCongestionControl(conn, s.Options.CongestionControl)
			h3t.TrackQUICConn("client", conn)
			return conn, nil
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
			s.tcpHTTPWarm = nil
		}
		s.IPHTTP = nil
	}
	s.IPHTTPConn = nil
}

// TCPConnectStreamHTTP3Authority returns the http3.Transport client-cache key for CONNECT-stream RoundTrip.
func TCPConnectStreamHTTP3Authority(options ClientOptions) string {
	port := int(options.ServerPort)
	if port <= 0 {
		port = 443
	}
	return http3.AuthorityAddr(net.JoinHostPort(strings.TrimSpace(options.Server), strconv.Itoa(port)))
}

// EnsureTCPHTTPQuicConn completes the QUIC handshake on the shared CONNECT-stream HTTP/3
// transport once per TCPHTTP instance. Parallel dials coalesce via singleflight; s.Mu is not
// held during network I/O.
func EnsureTCPHTTPQuicConn(s *CoreSession) error {
	if CurrentUDPHTTPLayer(s) == option.MasqueHTTPLayerH2 {
		return nil
	}
	s.Mu.Lock()
	EnsureTCPHTTPTransportLockedAssumeMu(s)
	tr := s.TCPHTTP
	if tr == s.tcpHTTPWarm {
		s.Mu.Unlock()
		return nil
	}
	s.Mu.Unlock()
	if tr == nil {
		return errors.New("nil CONNECT-stream HTTP/3 transport")
	}
	_, err, _ := s.tcpHTTPWarmFlight.Do(warmFlightKey(tr), func() (any, error) {
		s.Mu.Lock()
		if s.TCPHTTP != tr {
			s.Mu.Unlock()
			return nil, errors.New("CONNECT-stream HTTP/3 transport replaced during warm")
		}
		if tr == s.tcpHTTPWarm {
			s.Mu.Unlock()
			return nil, nil
		}
		s.Mu.Unlock()

		warmCtx, cancel := context.WithTimeout(context.Background(), connectStreamQUICWarmTimeout)
		defer cancel()
		authority := TCPConnectStreamHTTP3Authority(s.Options)
		port := int(s.Options.ServerPort)
		if port <= 0 {
			port = 443
		}
		dialTarget := MasqueDialTarget(QuicDialCandidateHost(s.Options), port)
		log.Printf("masque_tcp_quic_warm_start tag=%s authority=%s dial=%s",
			strings.TrimSpace(s.Options.Tag), authority, dialTarget)
		if err := tr.EnsureClientConn(warmCtx, authority); err != nil {
			log.Printf("masque_tcp_quic_warm_fail tag=%s authority=%s dial=%s err=%v",
				strings.TrimSpace(s.Options.Tag), authority, dialTarget, err)
			return nil, fmt.Errorf("quic dial %s: %w", dialTarget, err)
		}
		log.Printf("masque_tcp_quic_warm_ok tag=%s authority=%s dial=%s",
			strings.TrimSpace(s.Options.Tag), authority, dialTarget)
		s.Mu.Lock()
		if s.TCPHTTP == tr {
			s.tcpHTTPWarm = tr
		}
		s.Mu.Unlock()
		return nil, nil
	})
	return err
}

// WarmTCPConnectStreamHTTP3Transport completes the QUIC handshake on a CONNECT-stream transport (P6 warm dial).
func WarmTCPConnectStreamHTTP3Transport(ctx context.Context, s *CoreSession, tr *http3.Transport) error {
	if tr == nil {
		return errors.New("nil CONNECT-stream HTTP/3 transport")
	}
	warmCtx, cancel := context.WithTimeout(context.Background(), connectStreamQUICWarmTimeout)
	defer cancel()
	if ctx != nil {
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		default:
		}
	}
	if err := tr.EnsureClientConn(warmCtx, TCPConnectStreamHTTP3Authority(s.Options)); err != nil {
		return err
	}
	if s.TCPHTTP == tr {
		s.Mu.Lock()
		s.tcpHTTPWarm = tr
		s.Mu.Unlock()
	}
	return nil
}

func warmFlightKey(tr *http3.Transport) string {
	return fmt.Sprintf("%p", tr)
}

// NewTCPConnectStreamHTTP3Transport builds the CONNECT-stream HTTP/3 overlay transport.
func NewTCPConnectStreamHTTP3Transport(s *CoreSession) *http3.Transport {
	tcpTLS := ClientTLSConfig(s.Options)
	quicCfgBase := TCPConnectStreamQUICConfig(s.Options)
	quicDial := QuicDialWithPolicy("client_connect_stream", s.Options.QUICDial)
	transport := &http3.Transport{
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
			h3t.FinalizeConnectStreamQUICConfig(cfg)
			conn, err := quicDial(ctx, target, tlsCfg, cfg)
			if err != nil {
				return nil, err
			}
			h3t.ApplyExternalCongestionControl(conn, s.Options.CongestionControl)
			h3t.TrackQUICConn("client", conn)
			return conn, nil
		},
	}
	ApplyWarpHTTP3TransportFields(transport, s.Options)
	return transport
}

// EnsureTCPHTTPTransportLockedAssumeMu lazily allocates CONNECT-stream HTTP/3 transport.
// Caller must hold s.Mu. No-op when overlay is H2 or TCPHTTP is already set.
func EnsureTCPHTTPTransportLockedAssumeMu(s *CoreSession) {
	if CurrentUDPHTTPLayer(s) == option.MasqueHTTPLayerH2 || s.TCPHTTP != nil {
		return
	}
	s.TCPHTTP = NewTCPConnectStreamHTTP3Transport(s)
}

// ResetTCPHTTPTransport rebuilds the CONNECT-stream HTTP overlay transport (H3 or H2 pool)
// and completes one QUIC warm on the new transport. Session-level only — never from per-dial retry.
func ResetTCPHTTPTransport(s *CoreSession, host TCPHTTPTransportHost) {
	if CurrentUDPHTTPLayer(s) == option.MasqueHTTPLayerH2 {
		host.ResetH2ConnectStreamTransportLockedAssumeMu()
		return
	}
	s.Mu.Lock()
	if s.TCPHTTP != nil {
		if s.TCPHTTP == s.IPHTTP {
			s.IPHTTP = nil
			s.IPHTTPConn = nil
		}
		s.TCPHTTP.Close()
	}
	s.tcpHTTPWarm = nil
	s.TCPHTTP = NewTCPConnectStreamHTTP3Transport(s)
	s.Mu.Unlock()
	if err := EnsureTCPHTTPQuicConn(s); err != nil {
		log.Printf("masque_tcp_quic_warm_after_reset tag=%s err=%v",
			strings.TrimSpace(s.Options.Tag), err)
	}
}
