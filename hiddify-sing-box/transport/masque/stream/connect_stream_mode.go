package stream

import (
	"context"
	"strings"
)

const (
	ConnectStreamModeSingleBidi = "single_bidi"
	ConnectStreamModeThinBidi   = "thin_bidi"
	ConnectStreamModeSplitLegs  = "split_legs"
)

type connectStreamModeKey struct{}

// ContextWithConnectStreamMode tags a CONNECT-stream dial with the client dataplane mode.
func ContextWithConnectStreamMode(ctx context.Context, mode string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, connectStreamModeKey{}, NormalizeConnectStreamMode(mode))
}

// ConnectStreamModeFromContext returns the effective CONNECT-stream dataplane mode.
func ConnectStreamModeFromContext(ctx context.Context) string {
	if ctx == nil {
		return ConnectStreamModeSingleBidi
	}
	mode, _ := ctx.Value(connectStreamModeKey{}).(string)
	if mode == "" {
		return ConnectStreamModeSingleBidi
	}
	return mode
}

// NormalizeConnectStreamMode maps config values to canonical mode names.
func NormalizeConnectStreamMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case ConnectStreamModeThinBidi:
		return ConnectStreamModeThinBidi
	case ConnectStreamModeSplitLegs:
		return ConnectStreamModeSplitLegs
	default:
		return ConnectStreamModeSingleBidi
	}
}

// IsConnectStreamThinBidi reports whether the dial should use the Invisv-shaped thin client path.
func IsConnectStreamThinBidi(ctx context.Context) bool {
	return ConnectStreamModeFromContext(ctx) == ConnectStreamModeThinBidi
}
