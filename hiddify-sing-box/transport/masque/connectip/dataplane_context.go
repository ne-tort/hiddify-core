package connectip

import "context"

// DataplaneContext returns a context for CONNECT-IP packet-plane work that does not
// propagate cancellation from the inbound open/dial caller. sing-box may pass a
// short-lived ctx into OpenIPSession or ListenPacket; after the tunnel opens the
// relay lifetime must not track that ctx (parity protocol/masque/server DataplaneContext).
func DataplaneContext(openCtx context.Context) context.Context {
	return context.WithoutCancel(openCtx)
}
