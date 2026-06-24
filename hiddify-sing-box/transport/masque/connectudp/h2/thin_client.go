package h2

import (
	"context"

	"golang.org/x/net/http2"
)

// dedicatedOverlayTransport returns a per-UDPFlow EnsureTransport when NewTransport is wired.
func dedicatedOverlayTransport(cfg H2OverlayDialConfig) (H2OverlayDialConfig, func()) {
	if cfg.NewTransport == nil {
		return cfg, nil
	}
	var tr *http2.Transport
	cfg2 := cfg
	cfg2.EnsureTransport = func(ctx context.Context) (*http2.Transport, error) {
		select {
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		default:
		}
		if tr != nil {
			return tr, nil
		}
		var err error
		tr, err = cfg.NewTransport()
		return tr, err
	}
	onClose := func() {
		if tr != nil {
			CloseClientTransport(tr)
			tr = nil
		}
	}
	return cfg2, onClose
}
