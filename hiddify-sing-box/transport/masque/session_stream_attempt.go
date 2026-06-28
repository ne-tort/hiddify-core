package masque

import (
	"context"
	"errors"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/quic-go/quic-go/http3"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque/session"
	strm "github.com/sagernet/sing-box/transport/masque/stream"
	strmclient "github.com/sagernet/sing-box/transport/masque/stream/client"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/yosida95/uritemplate/v3"
)

func (s *coreSession) streamAttemptHost() strmclient.SessionAttemptHost {
	return strmclient.SessionAttemptHost{
		Prepare:              s.streamAttemptPrepareLocked,
		Dial:                 s.streamAttemptDialOnce,
		BracketRetry:   MasqueTCPBracketRetryEligible,
		OnBracketRetry: s.streamAttemptOnBracketAutoRetry,
		RecordSuccess:        s.streamAttemptRecordSuccess,
		Tag:                  func() string { return s.Options.Tag },
	}
}

func (s *coreSession) streamAttemptPrepareLocked() (strm.AttemptSnapshot, func(), error) {
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
			return strm.AttemptSnapshot{}, nil, errors.Join(session.ErrCapability, E.Cause(err, "invalid TCP MASQUE template"))
		}
		s.TemplateTCP = t
	}
	templateTCP := s.TemplateTCP
	options := s.Options
	if httpLayer != option.MasqueHTTPLayerH2 {
		session.EnsureTCPHTTPTransportLockedAssumeMu(&s.CoreSession)
	}
	var tcpHTTP *http3.Transport
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

func (s *coreSession) streamAttemptDialOnce(
	ctx context.Context,
	snap strm.AttemptSnapshot,
	destination M.Socksaddr,
	targetHost string,
	targetPort uint16,
	pathBracket bool,
) (net.Conn, *url.URL, error) {
	return s.dialTCPStreamOnce(ctx, snap.TemplateTCP, s.Options, destination, snap.HTTPLayer, snap.TCPHTTP, targetHost, targetPort, pathBracket)
}

func (s *coreSession) streamAttemptOnBracketAutoRetry(tag, targetHost string, tcpURL *url.URL) {
	log.Printf("masque_tcp_ipv6_bracket_auto_retry tag=%s target_host=%s url=%s", strings.TrimSpace(tag), targetHost, MasqueTCPConnectStreamRequestURL(tcpURL))
}

func (s *coreSession) streamAttemptRecordSuccess(snap strm.AttemptSnapshot, tcpURL *url.URL) {
	options := s.Options
	if snap.HTTPLayer == option.MasqueHTTPLayerH2 {
		s.maybeRecordHTTPLayerCacheSuccess(option.MasqueHTTPLayerH2)
		logTarget, dialAddr := tcpMasqueConnectStreamChosenLogFields(tcpURL, options)
		log.Printf("masque_http_layer_chosen layer=h2 tag=%s tcp_stream=1 target=%s dial=%s", strings.TrimSpace(options.Tag), logTarget, dialAddr)
		s.resetHTTPFallbackBudgetAfterSuccess()
		return
	}
	s.maybeRecordHTTPLayerCacheSuccess(option.MasqueHTTPLayerH3)
	logTarget, dialAddr := tcpMasqueConnectStreamChosenLogFields(tcpURL, options)
	log.Printf("masque_http_layer_chosen layer=h3 tag=%s tcp_stream=1 target=%s dial=%s", strings.TrimSpace(options.Tag), logTarget, dialAddr)
	s.resetHTTPFallbackBudgetAfterSuccess()
}
