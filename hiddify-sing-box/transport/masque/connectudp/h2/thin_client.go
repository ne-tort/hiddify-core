package h2

import (
	"context"
	"os"
	"strconv"
	"strings"

	"golang.org/x/net/http2"
)

const envH2ThinClient = "MASQUE_H2_THIN_CLIENT"

// ThinClientConfigured enables R8/h2o-shaped upload path (immediate per-chunk flush when upload-only).
func ThinClientConfigured() bool {
	v := strings.TrimSpace(os.Getenv(envH2ThinClient))
	if v == "" {
		return false
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false
	}
	return b
}

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
