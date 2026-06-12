package connectip

// TCPIngressDeliverHooks binds session state for inbound TCP datagram delivery.
type TCPIngressDeliverHooks struct {
	ActiveNetstack    func() *Netstack
	InstallInflight   func() bool
	NetstackForInject func() *Netstack
	EnqueuePreTCP     func(pkt []byte)
	OnAfterDeliver    func(pkt []byte, ns *Netstack)
}

// DeliverTCPIngress injects one proxied TCP datagram into the CONNECT-IP netstack and
// schedules QUIC send wake for upload ACK-clock / download DATA delivery.
func DeliverTCPIngress(pkt []byte, h TCPIngressDeliverHooks) bool {
	deliver := func(ns *Netstack) {
		ns.InjectInboundClone(pkt)
		if IPv4TCPHasPayload(pkt) {
			ns.ScheduleOutboundDrain()
		}
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
