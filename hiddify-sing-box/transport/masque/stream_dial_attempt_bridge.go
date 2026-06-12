package masque

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque/session"
	strm "github.com/sagernet/sing-box/transport/masque/stream"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/yosida95/uritemplate/v3"
)

type tcpStreamAttemptDialHost struct {
	s *coreSession
}

func (h tcpStreamAttemptDialHost) PrepareAttemptLocked() (strm.AttemptSnapshot, func(), error) {
	s := h.s
	s.Mu.Lock()
	httpLayer := s.currentUDPHTTPLayer()
	if s.TemplateTCP == nil {
		port := int(s.Options.ServerPort)
		if port <= 0 {
			port = 443
		}
		auth := net.JoinHostPort(strings.TrimSpace(s.Options.Server), strconv.Itoa(port))
		raw := ExpandMasqueHTTPSURI(s.Options.TemplateTCP, auth)
		if raw == "" {
			raw = "https://" + auth + "/masque/tcp/{+target_host}/{target_port}"
		}
		raw = NormalizeMasqueTCPUDPTemplateTargetHost(raw)
		t, err := uritemplate.New(raw)
		if err != nil {
			s.Mu.Unlock()
			return strm.AttemptSnapshot{}, nil, errors.Join(ErrCapability, E.Cause(err, "invalid TCP MASQUE template"))
		}
		s.TemplateTCP = t
	}
	templateTCP := s.TemplateTCP
	options := s.Options
	var tcpHTTP *http3.Transport
	if httpLayer != option.MasqueHTTPLayerH2 && s.TCPHTTP == nil {
		tlsMerged := masqueClientTLSConfig(options)
		s.TCPHTTP = &http3.Transport{
			EnableDatagrams:    masqueTCPConnectStreamHTTP3EnableDatagrams(options),
			DisableCompression: true,
			TLSClientConfig:    tlsMerged,
			Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, _ *quic.Config) (*quic.Conn, error) {
				port := int(s.Options.ServerPort)
				if port <= 0 {
					port = 443
				}
				target := masqueDialTarget(masqueQuicDialCandidateHost(s.Options), port)
				cfg := session.ApplyQUICExperimentalOptions(
					masqueTCPConnectStreamQUICConfig(options),
					options.QUICExperimental,
				)
				return s.quicDialWithPolicy("client_connect_stream")(ctx, target, tlsCfg, cfg)
			},
		}
		applyWarpMasqueHTTP3TransportFields(s.TCPHTTP, options)
	}
	if httpLayer != option.MasqueHTTPLayerH2 {
		tcpHTTP = s.TCPHTTP
	}
	s.Mu.Unlock()
	return strm.AttemptSnapshot{
		HTTPLayer:          httpLayer,
		HTTPLayerH2:        option.MasqueHTTPLayerH2,
		TemplateTCP:        templateTCP,
		TCPHTTP:            tcpHTTP,
		PathBracketDefault: options.TCPIPv6PathBracket,
	}, func() {}, nil
}

func (h tcpStreamAttemptDialHost) DialOnce(
	ctx context.Context,
	snap strm.AttemptSnapshot,
	destination M.Socksaddr,
	targetHost string,
	targetPort uint16,
	pathBracket bool,
) (net.Conn, *url.URL, error) {
	return h.s.dialTCPStreamOnce(ctx, snap.TemplateTCP, h.s.Options, destination, snap.HTTPLayer, snap.TCPHTTP, targetHost, targetPort, pathBracket)
}

func (h tcpStreamAttemptDialHost) BracketRetryEligible(targetHost string) bool {
	return MasqueTCPBracketRetryEligible(targetHost)
}

func (h tcpStreamAttemptDialHost) OnBracketAutoRetry(tag, targetHost string, tcpURL *url.URL) {
	log.Printf("masque_tcp_ipv6_bracket_auto_retry tag=%s target_host=%s url=%s", strings.TrimSpace(tag), targetHost, MasqueTCPConnectStreamRequestURL(tcpURL))
}

func (h tcpStreamAttemptDialHost) RecordAttemptSuccess(snap strm.AttemptSnapshot, tcpURL *url.URL) {
	options := h.s.Options
	if snap.HTTPLayer == option.MasqueHTTPLayerH2 {
		h.s.maybeRecordHTTPLayerCacheSuccess(option.MasqueHTTPLayerH2)
		logTarget, dialAddr := tcpMasqueConnectStreamChosenLogFields(tcpURL, options)
		log.Printf("masque_http_layer_chosen layer=h2 tag=%s tcp_stream=1 target=%s dial=%s", strings.TrimSpace(options.Tag), logTarget, dialAddr)
		h.s.resetHTTPFallbackBudgetAfterSuccess()
		return
	}
	h.s.maybeRecordHTTPLayerCacheSuccess(option.MasqueHTTPLayerH3)
	logTarget, dialAddr := tcpMasqueConnectStreamChosenLogFields(tcpURL, options)
	log.Printf("masque_http_layer_chosen layer=h3 tag=%s tcp_stream=1 target=%s dial=%s", strings.TrimSpace(options.Tag), logTarget, dialAddr)
	h.s.resetHTTPFallbackBudgetAfterSuccess()
}

func (h tcpStreamAttemptDialHost) ConnectStreamTag() string {
	return h.s.Options.Tag
}
