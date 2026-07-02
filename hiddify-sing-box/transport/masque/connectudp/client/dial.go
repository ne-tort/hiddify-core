package client

import (
	"context"
	"crypto/tls"
	"net"
	"strings"

	qmasque "github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque/connectudp/diag"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/yosida95/uritemplate/v3"
)

// QUICClientConfig builds a masque-go CONNECT-UDP QUIC client.
type QUICClientConfig struct {
	TLSClientConfig *tls.Config
	QUICConfig      *quic.Config
	QUICDial        func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error)
	BearerToken     string
	LegacyH3Extras  bool
}

// NewQUICClient returns a masque-go client for CONNECT-UDP over HTTP/3 datagrams.
func NewQUICClient(cfg QUICClientConfig) *qmasque.Client {
	return &qmasque.Client{
		TLSClientConfig: cfg.TLSClientConfig,
		QUICConfig:      cfg.QUICConfig,
		QUICDial:        cfg.QUICDial,
		BearerToken:     cfg.BearerToken,
		LegacyH3Extras:  cfg.LegacyH3Extras,
	}
}

// ErrQUICClientNotInitialized is returned when H3 CONNECT-UDP is attempted without a masque-go client.
var ErrQUICClientNotInitialized = E.New("masque CONNECT-UDP QUIC client not initialized")

// TrimTag returns a trimmed observability tag.
func TrimTag(tag string) string {
	return strings.TrimSpace(tag)
}

func dialH2(ctx context.Context, host DialHost, obs ObservabilityInput, template *uritemplate.Template, target string) (net.PacketConn, error) {
	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	default:
	}
	if template == nil {
		return nil, host.ErrTemplateNotConfigured()
	}
	var logTarget, dialAddr string
	if diag.Enabled() {
		logTarget, dialAddr = ConnectObservabilityFields(obs)
		diag.Logf("masque_http_layer_attempt layer=h2 tag=%s connect_udp=1 target=%s dial=%s", host.Tag(), logTarget, dialAddr)
	}
	pc, err := host.DialOverHTTP2(ctx, template, target)
	if err == nil {
		host.RecordHTTPLayerSuccess(option.MasqueHTTPLayerH2)
		if diag.Enabled() {
			if logTarget == "" && dialAddr == "" {
				logTarget, dialAddr = ConnectObservabilityFields(obs)
			}
			diag.Logf("masque_http_layer_chosen layer=h2 tag=%s connect_udp=1 target=%s dial=%s", host.Tag(), logTarget, dialAddr)
		}
		host.ResetHTTPFallbackBudgetAfterSuccess()
	}
	return pc, err
}

func dialH3(ctx context.Context, host DialHost, obs ObservabilityInput, client *qmasque.Client, template *uritemplate.Template, target string) (net.PacketConn, error) {
	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	default:
	}
	if template == nil {
		return nil, host.ErrTemplateNotConfigured()
	}
	var logTarget, dialAddr string
	if diag.Enabled() {
		logTarget, dialAddr = ConnectObservabilityFields(obs)
		diag.Logf("masque_http_layer_attempt layer=h3 tag=%s connect_udp=1 target=%s dial=%s", host.Tag(), logTarget, dialAddr)
	}
	pc, err := host.DialH3(ctx, client, template, target)
	if err == nil {
		host.RecordHTTPLayerSuccess(option.MasqueHTTPLayerH3)
		if diag.Enabled() {
			if logTarget == "" && dialAddr == "" {
				logTarget, dialAddr = ConnectObservabilityFields(obs)
			}
			diag.Logf("masque_http_layer_chosen layer=h3 tag=%s connect_udp=1 target=%s dial=%s", host.Tag(), logTarget, dialAddr)
		}
		host.ResetHTTPFallbackBudgetAfterSuccess()
	}
	return pc, err
}

// DialH3Production dials CONNECT-UDP via connectudp/conn H3Conn (W-UDP-1 client path).
func DialH3Production(
	ctx context.Context,
	hook func(context.Context, *qmasque.Client, *uritemplate.Template, string) (net.PacketConn, error),
	client *qmasque.Client,
	template *uritemplate.Template,
	target string,
) (net.PacketConn, error) {
	if hook != nil {
		return hook(ctx, client, template, target)
	}
	if client == nil {
		return nil, ErrQUICClientNotInitialized
	}
	pc, _, err := client.DialAddr(ctx, template, target)
	return pc, err
}

// DialAddr dials CONNECT-UDP on the current overlay (H2 capsule or H3 datagram).
func DialAddr(ctx context.Context, host DialHost, obs ObservabilityInput, client *qmasque.Client, template *uritemplate.Template, target string) (net.PacketConn, error) {
	if host.CurrentHTTPLayer() == option.MasqueHTTPLayerH2 {
		return dialH2(ctx, host, obs, template, target)
	}
	return dialH3(ctx, host, obs, client, template, target)
}
