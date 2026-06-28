package ingress

// TCPDeliverHooks binds session state for inbound TCP datagram delivery.
type TCPDeliverHooks struct {
	ActiveNetstack    func() Netstack
	InstallInflight   func() bool
	NetstackForInject func() Netstack
	EnqueuePreTCP     func(pkt []byte)
	OnAfterDeliver    func(pkt []byte, ns Netstack)
}

// DeliverTCP injects one proxied TCP datagram into the CONNECT-IP netstack.
// Ingress QUIC wake is coalesced via OnAfterDeliver + host IngressFlushAckWake.
func DeliverTCP(pkt []byte, h TCPDeliverHooks) bool {
	deliver := func(ns Netstack) {
		ns.InjectInboundOwned(cloneInboundFrame(pkt))
		if h.OnAfterDeliver != nil {
			h.OnAfterDeliver(pkt, ns)
		}
	}
	if h.ActiveNetstack != nil {
		if ns := h.ActiveNetstack(); ns != nil {
			deliver(ns)
			return true
		}
	}
	if h.InstallInflight != nil && h.InstallInflight() {
		if h.EnqueuePreTCP != nil {
			h.EnqueuePreTCP(pkt)
		}
		return true
	}
	if h.NetstackForInject != nil {
		if ns := h.NetstackForInject(); ns != nil {
			deliver(ns)
			return true
		}
	}
	return false
}
