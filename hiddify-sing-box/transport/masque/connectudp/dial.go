package connectudp

import (
	"context"
	"log"
	"net"
	"strings"

	qmasque "github.com/quic-go/masque-go"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/yosida95/uritemplate/v3"
)

// DialHost wires production CONNECT-UDP overlay dial from package masque.
type DialHost interface {
	Tag() string
	CurrentHTTPLayer() string
	DialOverHTTP2(ctx context.Context, template *uritemplate.Template, target string) (net.PacketConn, error)
	DialH3(ctx context.Context, client *qmasque.Client, template *uritemplate.Template, target string) (net.PacketConn, error)
	RecordHTTPLayerSuccess(layer string)
	ResetHTTPFallbackBudgetAfterSuccess()
	ErrTemplateNotConfigured() error
}

// DialAddr dials CONNECT-UDP on the current overlay (H2 capsule or H3 datagram).
func DialAddr(ctx context.Context, host DialHost, obs ObservabilityInput, client *qmasque.Client, template *uritemplate.Template, target string) (net.PacketConn, error) {
	if host.CurrentHTTPLayer() == option.MasqueHTTPLayerH2 {
		select {
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		default:
		}
		if template == nil {
			return nil, host.ErrTemplateNotConfigured()
		}
		logTarget, dialAddr := ConnectObservabilityFields(obs)
		log.Printf("masque_http_layer_attempt layer=h2 tag=%s connect_udp=1 target=%s dial=%s", host.Tag(), logTarget, dialAddr)
		pc, err := host.DialOverHTTP2(ctx, template, target)
		if err == nil {
			host.RecordHTTPLayerSuccess(option.MasqueHTTPLayerH2)
			log.Printf("masque_http_layer_chosen layer=h2 tag=%s connect_udp=1 target=%s dial=%s", host.Tag(), logTarget, dialAddr)
			host.ResetHTTPFallbackBudgetAfterSuccess()
		}
		return pc, err
	}
	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	default:
	}
	if template == nil {
		return nil, host.ErrTemplateNotConfigured()
	}
	logTarget, dialAddr := ConnectObservabilityFields(obs)
	log.Printf("masque_http_layer_attempt layer=h3 tag=%s connect_udp=1 target=%s dial=%s", host.Tag(), logTarget, dialAddr)
	pc, err := host.DialH3(ctx, client, template, target)
	if err == nil {
		host.RecordHTTPLayerSuccess(option.MasqueHTTPLayerH3)
		log.Printf("masque_http_layer_chosen layer=h3 tag=%s connect_udp=1 target=%s dial=%s", host.Tag(), logTarget, dialAddr)
		host.ResetHTTPFallbackBudgetAfterSuccess()
	}
	return pc, err
}

// ErrQUICClientNotInitialized is returned when H3 CONNECT-UDP is attempted without a masque-go client.
var ErrQUICClientNotInitialized = E.New("masque CONNECT-UDP QUIC client not initialized")

// DialH3Production dials CONNECT-UDP via masque-go unless hook is set (tests).
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
	conn, _, err := client.DialAddr(ctx, template, target)
	return conn, err
}

// TrimTag returns a trimmed observability tag.
func TrimTag(tag string) string {
	return strings.TrimSpace(tag)
}
