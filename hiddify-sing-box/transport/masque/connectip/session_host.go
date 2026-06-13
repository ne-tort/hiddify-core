package connectip

// Production CONNECT-IP client session wiring uses two host adapters from package masque
// (connectip_session_bridge.go):
//
//  1. session.IPPlaneHost — open/reuse packet plane via session.OpenIPSessionLocked
//  2. IngressHost — shared ingress demux via NewIngress
//
// Both adapters share coreSession state; this file holds shared helpers to keep them consistent.

// WireTCPIngressDeliver builds TCPIngressDeliverHooks from session-scoped callbacks.
func WireTCPIngressDeliver(
	activeNetstack func() *Netstack,
	installInflight func() bool,
	netstackForInject func() *Netstack,
	enqueuePreTCP func([]byte),
	onAfterDeliver func([]byte, *Netstack),
) TCPIngressDeliverHooks {
	return TCPIngressDeliverHooks{
		ActiveNetstack:    activeNetstack,
		InstallInflight:   installInflight,
		NetstackForInject: netstackForInject,
		EnqueuePreTCP:     enqueuePreTCP,
		OnAfterDeliver:    onAfterDeliver,
	}
}
