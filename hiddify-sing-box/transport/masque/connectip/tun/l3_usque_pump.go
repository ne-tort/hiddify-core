package tun

import (
	cippump "github.com/sagernet/sing-box/transport/masque/connectip/pump"
)

// usquePumpOptions returns MaintainTunnel-shaped pump config.
func (b *L3OverlayBridge) usquePumpOptions(onLoopInEnd func()) cippump.TunnelOptions {
	opts := cippump.NormalizeTunnelOptions(cippump.TunnelOptions{
		NetBuffer: b.loopInNetBuffer(),
	})
	if b.hostKernelRelay() {
		opts.LoopInDrainOnly = true
		opts.LoopInUsqueImmediate = false
	}
	if onLoopInEnd != nil && !b.hostKernelRelay() {
		opts.OnLoopInEnd = onLoopInEnd
	}
	return opts
}

func (b *L3OverlayBridge) loopInNetBuffer() *cippump.NetBuffer {
	if b == nil {
		return cippump.DefaultNetBuffer()
	}
	b.mu.Lock()
	pool := b.egressPool
	b.mu.Unlock()
	if pool != nil {
		return pool
	}
	return cippump.DefaultNetBuffer()
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