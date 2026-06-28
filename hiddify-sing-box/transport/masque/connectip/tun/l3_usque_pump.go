package tun

import cippump "github.com/sagernet/sing-box/transport/masque/connectip/pump"

// usquePumpOptions returns MaintainTunnel-shaped pump config.
func (b *L3OverlayBridge) usquePumpOptions(onLoopInEnd func()) cippump.TunnelOptions {
	opts := cippump.TunnelOptions{
		LoopOutUsqueImmediate: true,
		LoopInUsqueImmediate:  true,
	}
	if b.hostKernelRelay() {
		// Host-kernel: yield after WriteIngress so LoopIn ReadHostEgress drains client ACKs
		// (bulk WriteIngress flood starves tun egress → kernel TCP zero-window drop).
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
