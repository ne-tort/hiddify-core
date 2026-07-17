package masque

import (
	"context"
	"errors"
	"log"
	"net"
	"net/url"
	"strings"

	"github.com/quic-go/quic-go/http3"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque/session"
	strm "github.com/sagernet/sing-box/transport/masque/stream"
	strmclient "github.com/sagernet/sing-box/transport/masque/stream/client"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

func (s *coreSession) streamAttemptHost() strmclient.SessionAttemptHost {
	return strmclient.SessionAttemptHost{
		Prepare:       s.streamAttemptPrepareLocked,
		Dial:          s.streamAttemptDialOnce,
		RecordSuccess: s.streamAttemptRecordSuccess,
		Tag:           func() string { return s.Options.Tag },
	}
}

func (s *coreSession) streamAttemptPrepareLocked() (strm.AttemptSnapshot, func(), error) {
	s.Mu.Lock()
	httpLayer := s.currentUDPHTTPLayer()
	if s.TemplateTCP == nil {
		s.Mu.Unlock()
		return strm.AttemptSnapshot{}, nil, errors.Join(session.ErrCapability, E.New("TCP MASQUE path template not initialized"))
	}
	templateTCP := s.TemplateTCP
	if httpLayer != option.MasqueHTTPLayerH2 {
		session.EnsureTCPHTTPTransportLockedAssumeMu(&s.CoreSession)
	}
	var tcpHTTP *http3.Transport
	if httpLayer != option.MasqueHTTPLayerH2 {
		tcpHTTP = s.TCPHTTP
	}
	s.Mu.Unlock()
	return strm.AttemptSnapshot{
		HTTPLayer:   httpLayer,
		HTTPLayerH2: option.MasqueHTTPLayerH2,
		TemplateTCP: templateTCP,
		TCPHTTP:     tcpHTTP,
	}, func() {}, nil
}

func (s *coreSession) streamAttemptDialOnce(
	ctx context.Context,
	snap strm.AttemptSnapshot,
	destination M.Socksaddr,
	targetHost string,
	targetPort uint16,
) (net.Conn, *url.URL, error) {
	return s.dialTCPStreamOnce(ctx, snap.TemplateTCP, s.Options, destination, snap.HTTPLayer, snap.TCPHTTP, targetHost, targetPort)
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
