package tun

import cippump "github.com/sagernet/sing-box/transport/masque/connectip/pump"

// usquePumpOptions returns MaintainTunnel-shaped pump config.
func (b *L3OverlayBridge) usquePumpOptions(onLoopInEnd func()) cippump.TunnelOptions {
	opts := cippump.NormalizeTunnelOptions(cippump.TunnelOptions{})
	if b.hostKernelRelay() {
		// Host-kernel: LoopIn coalesces ReadHostEgress; LoopOut yields after WriteIngress so
		// kernel TCP ACKs drain before bulk WriteIngress floods tun ingress (iperf -R stall).
		opts.LoopInUsqueImmediate = false
		opts.LoopOutYieldAfterWrite = true
	}
	if onLoopInEnd != nil && !b.hostKernelRelay() {
		opts.OnLoopInEnd = onLoopInEnd
	}
	return opts
}

// hostKernelRelay is true when LoopIn reads OS tun egress (prod Docker kernel TCP path).
func (b *L3OverlayBridge) hostKernelRelay() bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	ok := b.hostEgressRead != nil
	b.mu.Unlock()
	return ok
}