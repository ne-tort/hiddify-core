//go:build windows || darwin || linux

package tray

// UiLifecycle selects how tray double-click and UI spawn interact with the Flutter process.
//
// Detached (PathologyCli --tray): double-click → quit UI or spawn --reconnect-host.
// Embedded (in-process DLL tray): double-click → toggle window via `toggle` IPC.
type UiLifecycle int

const (
	// UiLifecycleDetached: UI is a separate process (PathologyCli host serve --tray).
	// Double-click toggles exit UI ↔ spawn --reconnect-host.
	UiLifecycleDetached UiLifecycle = iota
	// UiLifecycleEmbedded: UI and core DLL share one process.
	// Double-click toggles show ↔ hide via file signal; never kills the process.
	UiLifecycleEmbedded
)
