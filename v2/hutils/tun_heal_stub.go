//go:build !windows && !(linux && !android)

package hutils

// HealStickyTun is a no-op on platforms without desktop TUN leftovers.
func HealStickyTun() {}

// HealStickyTunForce is a no-op on platforms without desktop TUN leftovers.
func HealStickyTunForce() {}

// StickyTunLikelyPresent is always false on platforms without desktop TUN leftovers.
func StickyTunLikelyPresent() bool { return false }
