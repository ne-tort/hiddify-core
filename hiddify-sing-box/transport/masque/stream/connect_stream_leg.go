package stream

import "context"

type connectStreamLegKey struct{}

// ContextWithConnectStreamLeg tags a CONNECT-stream dial with P2 leg role (download/upload).
// Empty leg means single bidi tunnel (RouteBidiDuplex on).
func ContextWithConnectStreamLeg(ctx context.Context, leg string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, connectStreamLegKey{}, leg)
}

// ConnectStreamLegFromContext returns the P2 leg label, or "" for single bidi dial.
func ConnectStreamLegFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	leg, _ := ctx.Value(connectStreamLegKey{}).(string)
	return leg
}

// ConnectStreamRouteBidiDuplex reports whether this CONNECT tunnel shares one bidi stream
// for concurrent route upload+download (false for P2 download/upload legs).
func ConnectStreamRouteBidiDuplex(ctx context.Context) bool {
	return ConnectStreamLegFromContext(ctx) == ""
}
