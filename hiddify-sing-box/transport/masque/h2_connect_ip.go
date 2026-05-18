package masque

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"

	connectip "github.com/quic-go/connect-ip-go"
)

func masqueConnectIPDialOptions(opts ClientOptions) connectip.DialOptions {
	dopts := connectip.DialOptions{}
	if u := strings.TrimSpace(opts.ClientBasicUsername); u != "" {
		dopts.ExtraRequestHeaders = make(http.Header)
		dopts.ExtraRequestHeaders.Set("Authorization", masqueClientBasicAuthHeader(u, opts.ClientBasicPassword))
	} else if tok := strings.TrimSpace(opts.ServerToken); tok != "" {
		dopts.BearerToken = tok
	}
	if wp := strings.TrimSpace(opts.WarpConnectIPProtocol); wp != "" {
		dopts.ExtendedConnectProtocol = wp
		if strings.EqualFold(wp, "cf-connect-ip") {
			dopts.HTTP2LegacyConnect = true
		}
	}
	return dopts
}

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

	proto := strings.TrimSpace(s.options.WarpConnectIPProtocol)
	primaryHost := strings.TrimSpace(masqueQuicDialCandidateHost(s.options))
	altHost := ""
	if strings.EqualFold(proto, "cf-connect-ip") {
		altHost = warpMasqueH2AlternateDialHost(primaryHost)
	}

	tr, err := s.ensureH2UDPTransport(ctx)
	if err != nil {
		return nil, fmt.Errorf("masque connect-ip h2: %w", err)
	}
	rt := s.getTCPRoundTripper(tr)

	opts := masqueConnectIPDialOptions(s.options)
	conn, rsp, err := connectip.DialHTTP2(ctx, rt, s.templateIP, opts)
	if err != nil {
		if altHost != "" && isMasqueH2ExtendedConnectUnsupportedByPeer(err) {
			log.Printf("masque h2 cf-connect-ip: tcp dial uses sibling %s of quic dataplane %s; peer omits RFC8441 SETTINGS_ENABLE_CONNECT_PROTOCOL (cannot run cf-connect-ip over H2 on this edge) tag=%s",
				altHost, primaryHost, strings.TrimSpace(s.options.Tag))
		}
		return nil, fmt.Errorf("masque connect-ip h2: %w", err)
	}
	s.logCfConnectIPHTTPResponse(rsp)
	if err := s.warpMasqueConnectIPBootstrap(conn); err != nil {
		return nil, err
	}
	if err := s.genericMasqueConnectIPBootstrap(conn); err != nil {
		return nil, err
	}
	return conn, nil
}
