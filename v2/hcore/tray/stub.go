//go:build !windows && !darwin && !linux

package tray

// Options configures the unified core-owned system tray.
type Options struct {
	UIExe    string
	BasePath string
	Lang     string
}

// StartTray is a no-op on unsupported platforms.
func StartTray(_ Options) {}

// Done returns nil when StartTray was never called.
func Done() <-chan struct{} {
	return nil
}

// StopTray is a no-op on unsupported platforms.
func StopTray() {}

// SpawnUIReconnect is a no-op on unsupported platforms.
func SpawnUIReconnect() {}
