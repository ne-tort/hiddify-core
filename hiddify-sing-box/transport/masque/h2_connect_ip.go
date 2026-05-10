package masque

import (
	"context"
	"fmt"
	"log"
	"strings"

	connectip "github.com/quic-go/connect-ip-go"
)

func (s *coreSession) dialConnectIPHTTP2(ctx context.Context) (*connectip.Conn, error) {
	dialAddr := masqueConnectIPOverlayDialAddr(s.options)
	select {
	case <-ctx.Done():
		s.clearHTTPFallbackConsumedAfterGivingUp()
		return nil, context.Cause(ctx)
	default:
	}
	if s.templateIP == nil {
		return nil, ErrConnectIPTemplateNotConfigured
	}
	log.Printf("masque_http_layer_attempt layer=h2 tag=%s connect_ip=1 dial=%s", strings.TrimSpace(s.options.Tag), dialAddr)

	tr, err := s.ensureH2UDPTransport(ctx)
	if err != nil {
		return nil, fmt.Errorf("masque connect-ip h2: %w", err)
	}
	rt := s.getTCPRoundTripper(tr)

	opts := connectip.DialOptions{
		BearerToken: strings.TrimSpace(s.options.ServerToken),
	}
	if wp := strings.TrimSpace(s.options.WarpConnectIPProtocol); wp != "" {
		opts.ExtendedConnectProtocol = wp
	}
	conn, _, err := connectip.DialHTTP2(ctx, rt, s.templateIP, opts)
	if err != nil {
		return nil, fmt.Errorf("masque connect-ip h2: %w", err)
	}
	return conn, nil
}
