package h2

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"

	h2c "github.com/sagernet/sing-box/transport/masque/h2"
	"golang.org/x/net/http2"
)

// OverlaySessionCallbacks supplies session wiring for CONNECT-UDP HTTP/2 overlay dial.
type OverlaySessionCallbacks struct {
	EnsureTransport          func(ctx context.Context) (*http2.Transport, error)
	NewTransport             func() (*http2.Transport, error)
	SetAuthHeader            func(h http.Header)
	Tag                      string
	WarpConnectIPProtocol    string
	QUICDialCandidateHost    string
	ResolveDialAddr          func() string
	ErrTemplateNotConfigured error
}

// H2OverlayDialConfigFromSession maps session callbacks into overlay dial config.
func H2OverlayDialConfigFromSession(cb OverlaySessionCallbacks) H2OverlayDialConfig {
	return H2OverlayDialConfig{
		EnsureTransport:          cb.EnsureTransport,
		NewTransport:             cb.NewTransport,
		SetAuthHeader:            cb.SetAuthHeader,
		Tag:                      cb.Tag,
		WarpConnectIPProtocol:    cb.WarpConnectIPProtocol,
		QUICDialCandidateHost:    cb.QUICDialCandidateHost,
		ResolveDialAddr:          cb.ResolveDialAddr,
		ErrTemplateNotConfigured: cb.ErrTemplateNotConfigured,
	}
}

// ClientTransportConfig builds a shared HTTP/2 MASQUE client transport (CONNECT-UDP/IP pool).
type ClientTransportConfig struct {
	TLSConfig          *tls.Config
	WarpConnectIPProtocol string
	DialOverrideHost   string
	TCPDial            func(ctx context.Context, network, address string) (net.Conn, error)
	MasqueTCPDialTLS   func(ctx context.Context, conn net.Conn, nextProtos []string, addr string) (net.Conn, error)
	DebugTCPDial       func(network, dialAddr, candidate string)
}

// NewClientTransport returns an HTTP/2 transport for CONNECT-UDP overlay dial.
func NewClientTransport(cfg ClientTransportConfig) (*http2.Transport, error) {
	dialOverrideHost := strings.TrimSpace(cfg.DialOverrideHost)
	alternateDialHost := ""
	if strings.EqualFold(strings.TrimSpace(cfg.WarpConnectIPProtocol), "cf-connect-ip") {
		alternateDialHost = WarpH2AlternateDialHost(dialOverrideHost)
	}
	debug := strings.TrimSpace(os.Getenv("HIDDIFY_MASQUE_CONNECT_IP_DEBUG")) == "1"
	return h2c.NewClientTransport(h2c.ClientDialConfig{
		TLSConfig:          cfg.TLSConfig,
		DialHostCandidates: H2DialHostCandidates(strings.TrimSpace(cfg.WarpConnectIPProtocol), dialOverrideHost, alternateDialHost),
		TCPDial:            cfg.TCPDial,
		MasqueTCPDialTLS:   cfg.MasqueTCPDialTLS,
		DebugTCPDial: func(network, dialAddr, candidate string) {
			if debug {
				log.Printf("masque h2 tcp dial attempt network=%s addr=%s candidate=%q", network, dialAddr, candidate)
			}
		},
	})
}

// EnsureTransportCached lazily builds and caches an HTTP/2 client transport slot.
func EnsureTransportCached(
	ctx context.Context,
	mu *sync.Mutex,
	slot **http2.Transport,
	forceNew bool,
	build func() (*http2.Transport, error),
) (*http2.Transport, error) {
	return h2c.EnsureTransportCached(ctx, mu, slot, forceNew, build)
}

// ResetTransportSlot closes and clears a cached HTTP/2 transport slot.
func ResetTransportSlot(mu *sync.Mutex, slot **http2.Transport) {
	h2c.ResetTransportSlot(mu, slot)
}

// CloseClientTransport closes an HTTP/2 client transport.
func CloseClientTransport(tr *http2.Transport) {
	h2c.CloseClientTransport(tr)
}

// CapsuleProtocolHeaderValue returns the Capsule-Protocol structured field for Extended CONNECT over HTTP/2.
func CapsuleProtocolHeaderValue() string {
	return h2c.CapsuleProtocolHeaderValue()
}
