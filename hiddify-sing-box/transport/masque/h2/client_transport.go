package h2

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"

	"github.com/sagernet/sing-box/transport/masque/netutil"
	"golang.org/x/net/http2"
)

// ClientDialConfig wires production HTTP/2 overlay dial for MASQUE dataplanes.
type ClientDialConfig struct {
	TLSConfig          *tls.Config
	DialHostCandidates []string
	TCPDial            func(ctx context.Context, network, addr string) (net.Conn, error)
	MasqueTCPDialTLS   func(ctx context.Context, conn net.Conn, nextProtos []string, addr string) (net.Conn, error)
	DebugTCPDial       func(network, dialAddr, candidate string)
}

// ClientTLSConfig returns an HTTP/2-only TLS config cloned from base (or a fresh config).
func ClientTLSConfig(base *tls.Config, serverName string) *tls.Config {
	if base == nil {
		return &tls.Config{
			NextProtos: []string{http2.NextProtoTLS},
			ServerName: serverName,
		}
	}
	cfg := base.Clone()
	cfg.NextProtos = []string{http2.NextProtoTLS}
	return cfg
}

// NewClientTransport builds an isolated http2.Transport for one MASQUE H2 pool role.
func NewClientTransport(cfg ClientDialConfig) (*http2.Transport, error) {
	tlsConf := cfg.TLSConfig
	if tlsConf == nil {
		tlsConf = ClientTLSConfig(nil, "")
	}
	dialTLS := func(ctx context.Context, network, addr string, tlsCfg *tls.Config) (net.Conn, error) {
		if cfg.TCPDial == nil {
			return nil, fmt.Errorf("masque h2: tcp dialer is not configured")
		}
		var lastErr error
		for _, candidateHost := range cfg.DialHostCandidates {
			dialAddr := addr
			if candidateHost != "" {
				if _, p, splitErr := net.SplitHostPort(addr); splitErr == nil {
					dialAddr = net.JoinHostPort(candidateHost, p)
				}
			}
			if cfg.DebugTCPDial != nil {
				cfg.DebugTCPDial(network, dialAddr, candidateHost)
			}
			conn, err := cfg.TCPDial(ctx, network, dialAddr)
			if err != nil {
				lastErr = fmt.Errorf("masque h2: tcp dial %s %s: %w", network, dialAddr, err)
				continue
			}
			if tc, ok := conn.(*net.TCPConn); ok {
				netutil.TuneMasqueTCPSocketBuffers(tc)
			}
			if cfg.MasqueTCPDialTLS != nil {
				tlsConn, err := cfg.MasqueTCPDialTLS(ctx, conn, tlsCfg.NextProtos, dialAddr)
				if err != nil {
					_ = conn.Close()
					lastErr = fmt.Errorf("masque h2: tls handshake %s %s: %w", network, dialAddr, err)
					continue
				}
				return tlsConn, nil
			}
			tlsConn := tls.Client(conn, tlsCfg)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				_ = conn.Close()
				lastErr = fmt.Errorf("masque h2: tls handshake %s %s: %w", network, dialAddr, err)
				continue
			}
			return tlsConn, nil
		}
		return nil, lastErr
	}
	tr, err := NewBulkHTTP2Transport(tlsConf, dialTLS)
	if err != nil {
		tr = &http2.Transport{
			TLSClientConfig:    tlsConf,
			DisableCompression: true,
			DialTLSContext:     dialTLS,
		}
		ApplyBulkHTTP2TransportDefaults(tr)
	}
	return tr, nil
}

// EnsureTransportCached returns a cached http2.Transport or builds one when the slot is empty.
func EnsureTransportCached(
	ctx context.Context,
	mu *sync.Mutex,
	slot **http2.Transport,
	tcpDialConfigured bool,
	build func() (*http2.Transport, error),
) (*http2.Transport, error) {
	if !tcpDialConfigured {
		return nil, fmt.Errorf("masque h2: tcp dialer is not configured")
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, context.Cause(ctx)
	}
	mu.Lock()
	defer mu.Unlock()
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, context.Cause(ctx)
	}
	if *slot != nil {
		return *slot, nil
	}
	tr, err := build()
	if err != nil {
		return nil, err
	}
	*slot = tr
	return tr, nil
}

// CloseClientTransport closes idle connections on an H2 client pool.
func CloseClientTransport(tr *http2.Transport) {
	if tr != nil {
		tr.CloseIdleConnections()
	}
}

// ResetTransportSlot closes and clears one cached http2.Transport.
func ResetTransportSlot(mu *sync.Mutex, slot **http2.Transport) {
	mu.Lock()
	defer mu.Unlock()
	CloseClientTransport(*slot)
	*slot = nil
}
