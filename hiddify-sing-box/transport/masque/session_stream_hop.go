package masque

import (
	"context"
	"errors"
	"net"

	"github.com/sagernet/sing-box/transport/masque/session"
	strmclient "github.com/sagernet/sing-box/transport/masque/stream/client"
	M "github.com/sagernet/sing/common/metadata"
)

func (s *coreSession) streamHopHost() strmclient.SessionHopHost {
	return strmclient.SessionHopHost{
		Dial: func(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
			return strmclient.DialAttempt(ctx, s.streamAttemptHost(), destination)
		},
		TryFallback:     s.tryHTTPFallbackSwitch,
		FallbackEnabled: func() bool { return s.HTTPLayerFallback },
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
	return strmclient.Plane{Host: s.streamHopHost()}.DialTCPStream(ctx, destination)
}
