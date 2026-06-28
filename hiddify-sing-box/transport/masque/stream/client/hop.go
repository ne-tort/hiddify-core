package client

import (
	"context"
	"net"

	strm "github.com/sagernet/sing-box/transport/masque/stream"
	M "github.com/sagernet/sing/common/metadata"
)

// HopChainHost wires session hop/fallback/overlay churn for CONNECT-stream dial.
type HopChainHost = strm.DialHopChainHost

// SessionHopHost wires CONNECT-stream hop-chain dial from coreSession.
type SessionHopHost struct {
	Dial             func(ctx context.Context, destination M.Socksaddr) (net.Conn, error)
	TryFallback      func(err error) bool
	FallbackEnabled  func() bool
	AuthFailure      func(err error) bool
	ClearFallback    func()
	RebuildOverlay   func()
	BeforeAdvanceHop func()
	AdvanceHop       func() (advanced bool, resetErr error)
}

func (h SessionHopHost) DialAttempt(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	return h.Dial(ctx, destination)
}

func (h SessionHopHost) TryHTTPFallbackSwitch(err error) bool {
	if h.TryFallback != nil {
		return h.TryFallback(err)
	}
	return false
}

func (h SessionHopHost) HTTPLayerFallbackEnabled() bool {
	if h.FallbackEnabled != nil {
		return h.FallbackEnabled()
	}
	return false
}

func (h SessionHopHost) IsAuthFailure(err error) bool {
	if h.AuthFailure != nil {
		return h.AuthFailure(err)
	}
	return false
}

func (h SessionHopHost) ClearHTTPFallbackAfterGiveUp() {
	if h.ClearFallback != nil {
		h.ClearFallback()
	}
}

func (h SessionHopHost) RebuildOverlayTransport() {
	if h.RebuildOverlay != nil {
		h.RebuildOverlay()
	}
}

func (h SessionHopHost) PreAdvanceHop() {
	if h.BeforeAdvanceHop != nil {
		h.BeforeAdvanceHop()
	}
}

func (h SessionHopHost) AdvanceHopLocked() (bool, error) {
	if h.AdvanceHop != nil {
		return h.AdvanceHop()
	}
	return false, nil
}

// Dial runs CONNECT-stream dial with http_layer fallback, overlay rebuild, and hop advance.
func Dial(ctx context.Context, host HopChainHost, destination M.Socksaddr) (net.Conn, error) {
	return strm.DialWithHopChain(ctx, host, destination)
}
