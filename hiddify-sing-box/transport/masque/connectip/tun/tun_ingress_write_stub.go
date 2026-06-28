//go:build !with_gvisor

package tun

import singtun "github.com/sagernet/sing-tun"

// TunIngressWrite returns wire→host inject via tun fd when gVisor is unavailable.
func TunIngressWrite(tunIf singtun.Tun) func([]byte) (int, error) {
	return func(p []byte) (int, error) { return tunIf.Write(p) }
}
