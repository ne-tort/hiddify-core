package masque

import (
	"context"
	"errors"
	"net"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/masque/session"
	strm "github.com/sagernet/sing-box/transport/masque/stream"
	strmclient "github.com/sagernet/sing-box/transport/masque/stream/client"
	M "github.com/sagernet/sing/common/metadata"
)

func (s *coreSession) streamHopHost() strmclient.SessionHopHost {
	return strmclient.SessionHopHost{
		Dial: func(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
			return strmclient.DialAttempt(ctx, s.streamAttemptHost(), destination)
		},
		TryFallback:     s.tryHTTPFallbackSwitch,
		FallbackEnabled: func() bool { return s.HTTPLayerAuto },
		AuthFailure: func(err error) bool {
			return errors.Is(err, session.ErrAuthFailed) || session.ClassifyError(err) == session.ErrorClassAuth
		},
		ClearFallback: s.clearHTTPFallbackConsumedAfterGivingUp,
		RebuildOverlay: s.resetTCPHTTPTransport,
		BeforeAdvanceHop: func() {
			if s.dialTCPStreamPreAdvanceHopHook != nil {
				s.dialTCPStreamPreAdvanceHopHook()
			}
		},
		AdvanceHop: s.streamAdvanceHopLocked,
	}
}

func (s *coreSession) streamAdvanceHopLocked() (bool, error) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	if !s.advanceHop() {
		return false, nil
	}
	if resetErr := s.resetHopTemplates(); resetErr != nil {
		return true, resetErr
	}
	return true, nil
}

func (s *coreSession) dialTCPStream(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	h3 := s.currentUDPHTTPLayer() != option.MasqueHTTPLayerH2
	if h3 {
		if err := session.EnsureTCPHTTPQuicConn(&s.CoreSession); err != nil {
			return nil, strm.JoinConnectStreamPhase("quic warm", err)
		}
	}
	queueCtx, queueCancel := strm.ConnectStreamQueueContext(ctx)
	defer queueCancel()
	if err := s.ConnectStreamInFlight.Acquire(queueCtx); err != nil {
		return nil, strm.JoinConnectStreamPhase("in-flight queue", err)
	}
	defer s.ConnectStreamInFlight.Release()
	budgetHeld := false
	if h3 {
		budgetWaitCtx, budgetWaitCancel := context.WithTimeout(context.Background(), strm.ConnectStreamHandshakeTimeout)
		err := s.ConnectStreamBudget.Acquire(budgetWaitCtx)
		budgetWaitCancel()
		if err != nil {
			return nil, strm.JoinConnectStreamPhase("stream budget", err)
		}
		budgetHeld = true
	}
	defer func() {
		if budgetHeld {
			s.ConnectStreamBudget.Release()
		}
	}()
	handshakeCtx, handshakeCancel := strm.ConnectStreamHandshakeContext(ctx)
	defer handshakeCancel()
	conn, err := strmclient.Plane{Host: s.streamHopHost()}.DialTCPStream(handshakeCtx, destination)
	if err != nil {
		return nil, err
	}
	if h3 {
		budgetHeld = false
		conn = session.AttachConnectStreamBudgetRelease(conn, s.ConnectStreamBudget)
	}
	return conn, nil
}
