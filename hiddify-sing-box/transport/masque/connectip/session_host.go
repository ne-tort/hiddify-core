package connectip

// Production CONNECT-IP client session wiring uses connectip/client.Plane (lazy ipPlaneOnce on
// coreSession, X-03 parity udpPlaneOnce) backed by masque adapters:
//
//  1. session.IPPlaneHost — connectIPSessionPlaneAdapter / ipPlaneHost
//  2. IngressHost — connectIPIngressHost via Plane.Ingress()
//
// Package connectip/client documents the intended client boundary; adapters stay in masque
// (cycle-safe). See connectip/client/session_host.go.

// WireTCPIngressDeliver builds TCPIngressDeliverHooks from session-scoped callbacks.
func WireTCPIngressDeliver(
	activeNetstack func() IngressNetstack,
	installInflight func() bool,
	netstackForInject func() IngressNetstack,
	enqueuePreTCP func([]byte),
	onAfterDeliver func([]byte, IngressNetstack),
) TCPIngressDeliverHooks {
	return TCPIngressDeliverHooks{
		ActiveNetstack: activeNetstack,
		InstallInflight: installInflight,
		NetstackForInject: netstackForInject,
		EnqueuePreTCP: enqueuePreTCP,
		OnAfterDeliver: onAfterDeliver,
	}
}

// WireTCPIngressDeliverFromStruct adapts *Netstack session hooks to IngressNetstack (masque glue).
func WireTCPIngressDeliverFromStruct(
	activeNetstack func() *Netstack,
	installInflight func() bool,
	netstackForInject func() *Netstack,
	enqueuePreTCP func([]byte),
	onAfterDeliver func([]byte, *Netstack),
) TCPIngressDeliverHooks {
	return WireTCPIngressDeliver(
		func() IngressNetstack {
			if activeNetstack == nil {
				return nil
			}
			if ns := activeNetstack(); ns != nil {
				return ns
			}
			return nil
		},
		installInflight,
		func() IngressNetstack {
			if netstackForInject == nil {
				return nil
			}
			if ns := netstackForInject(); ns != nil {
				return ns
			}
			return nil
		},
		enqueuePreTCP,
		func(pkt []byte, ns IngressNetstack) {
			if onAfterDeliver == nil || ns == nil {
				return
			}
			onAfterDeliver(pkt, ns.(*Netstack))
		},
	)
}
