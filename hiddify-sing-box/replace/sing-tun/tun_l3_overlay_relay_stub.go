//go:build with_gvisor && !linux

package tun

// SetL3OverlayKernelRelay is a no-op off Linux (host-kernel relay is Linux Docker path).
func (t *NativeTun) SetL3OverlayKernelRelay(enabled bool) {}
