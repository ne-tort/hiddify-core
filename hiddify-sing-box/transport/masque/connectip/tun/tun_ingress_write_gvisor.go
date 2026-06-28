//go:build with_gvisor

package tun

import (
	singtun "github.com/sagernet/sing-tun"
)

// TunIngressWrite returns wire→host inject for native L3 IP relay (usque Device.WritePacket parity).
// Prefer sing-tun WriteIngress (direct fd + virtio hdr); never tun.Write (TX GRO coalesces small ACKs).
func TunIngressWrite(tunIf singtun.Tun) func([]byte) (int, error) {
	return func(p []byte) (int, error) {
		if w, ok := tunIf.(singtun.HostIngressWriter); ok {
			return w.WriteIngress(p)
		}
		return tunIf.Write(p)
	}
}
