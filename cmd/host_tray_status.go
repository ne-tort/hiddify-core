//go:build windows || darwin || linux

package cmd

import (
	"context"
	"time"

	hcore "github.com/ne-tort/pathology-core/v2/hcore"

	"fyne.io/systray"
)

func startHostTrayStatusPoll(ctx context.Context, darkTheme bool) {
	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		var last hcore.CoreStates = -1
		applyTrayIcon(last, darkTheme)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				state := hcore.CurrentCoreState()
				if state != last {
					last = state
					applyTrayIcon(state, darkTheme)
				}
			}
		}
	}()
}

func applyTrayIcon(state hcore.CoreStates, darkTheme bool) {
	var icon []byte
	switch state {
	case hcore.CoreStates_STARTED:
		icon = trayIconConnected
	case hcore.CoreStates_STARTING, hcore.CoreStates_STOPPING:
		icon = trayIconConnecting
	default:
		if darkTheme {
			icon = trayIconDark
		} else {
			icon = trayIconDisconnected
		}
	}
	if len(icon) > 0 {
		systray.SetIcon(icon)
	}
}
