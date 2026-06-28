package pump

import "context"

// IngressDemux adapts connectip/pump/ingress frame dispatch for RunTunnel LoopOut.
type IngressDemux struct {
	Dispatch func(pkt []byte)
}

func (d *IngressDemux) DispatchIngress(_ context.Context, pkt []byte) error {
	if d == nil || d.Dispatch == nil || len(pkt) == 0 {
		return nil
	}
	d.Dispatch(pkt)
	return nil
}
