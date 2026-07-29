//go:build !windows && !(linux && !android)

package hutils

// HealStickyTun is a no-op on platforms without desktop TUN leftovers.
func HealStickyTun() {}
