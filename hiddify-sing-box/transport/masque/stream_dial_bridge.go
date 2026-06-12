package masque

import (
	"context"
	"errors"
	"net"

	strm "github.com/sagernet/sing-box/transport/masque/stream"
	M "github.com/sagernet/sing/common/metadata"
)

type tcpStreamDialHopHost struct {
	s *coreSession
}

func (h tcpStreamDialHopHost) DialAttempt(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	return strm.DialAttempt(ctx, tcpStreamAttemptDialHost{s: h.s}, destination)
}

func (h tcpStreamDialHopHost) TryHTTPFallbackSwitch(err error) bool {
	return h.s.tryHTTPFallbackSwitch(err)
}

func (h tcpStreamDialHopHost) HTTPLayerFallbackEnabled() bool {
	return h.s.HTTPLayerFallback
}

func (h tcpStreamDialHopHost) IsAuthFailure(err error) bool {
	return errors.Is(err, ErrAuthFailed) || ClassifyError(err) == ErrorClassAuth
}

func (h tcpStreamDialHopHost) ClearHTTPFallbackAfterGiveUp() {
	h.s.clearHTTPFallbackConsumedAfterGivingUp()
}

func (h tcpStreamDialHopHost) RebuildOverlayTransport() {
	h.s.resetTCPHTTPTransport()
}

func (h tcpStreamDialHopHost) PreAdvanceHop() {
	if h.s.dialTCPStreamPreAdvanceHopHook != nil {
		h.s.dialTCPStreamPreAdvanceHopHook()
	}
}

func (h tcpStreamDialHopHost) AdvanceHopLocked() (bool, error) {
	h.s.Mu.Lock()
	defer h.s.Mu.Unlock()
	if !h.s.advanceHop() {
		return false, nil
	}
	if resetErr := h.s.resetHopTemplates(); resetErr != nil {
		return true, resetErr
	}
	return true, nil
}

func (s *coreSession) dialTCPStream(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	return strm.DialWithHopChain(ctx, tcpStreamDialHopHost{s: s}, destination)
}
