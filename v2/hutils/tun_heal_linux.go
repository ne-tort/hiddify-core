//go:build linux && !android

package hutils

import (
	"os/exec"
	"time"
)

// HealStickyTun removes leftover Hiddify TUN interfaces/routes after a crash.
func HealStickyTun() {
	healStickyTunLinux()
}

// HealStickyTunForce is the same as HealStickyTun on Linux (no cooldown).
func HealStickyTunForce() {
	healStickyTunLinux()
}

// StickyTunLikelyPresent reports whether PathologyTunnel (or common leftovers) exist.
func StickyTunLikelyPresent() bool {
	name := TunInterfaceName
	if err := exec.Command("ip", "link", "show", "dev", name).Run(); err == nil {
		return true
	}
	for _, alt := range []string{"tun0", "singbox_tun"} {
		if err := exec.Command("ip", "link", "show", "dev", alt).Run(); err == nil {
			return true
		}
	}
	return false
}

func healStickyTunLinux() {
	name := TunInterfaceName
	_ = exec.Command("ip", "link", "set", name, "down").Run()
	time.Sleep(100 * time.Millisecond)
	_ = exec.Command("ip", "link", "delete", name).Run()
	// Common leftovers
	for _, alt := range []string{"tun0", "singbox_tun"} {
		_ = exec.Command("ip", "link", "set", alt, "down").Run()
		_ = exec.Command("ip", "link", "delete", alt).Run()
	}
}
