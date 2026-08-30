//go:build windows || darwin || linux

package tray

import (
	"context"
	"sync"
	"time"

	hcore "github.com/ne-tort/pathology-core/v2/hcore"

	"fyne.io/systray"
)

var (
	trayCtx              context.Context
	transitionWatchMu    sync.Mutex
	transitionWatching   bool
)

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

func refreshConnectionUI(state hcore.CoreStates) {
	refreshConnectionMenu(state)
	applyTrayIcon(state, darkMenu)
}

// watchCoreTransitions polls briefly only while STARTING/STOPPING (icon + toggle label).
func watchCoreTransitions(ctx context.Context) {
	transitionWatchMu.Lock()
	if transitionWatching {
		transitionWatchMu.Unlock()
		return
	}
	transitionWatching = true
	transitionWatchMu.Unlock()

	go func() {
		defer func() {
			transitionWatchMu.Lock()
			transitionWatching = false
			transitionWatchMu.Unlock()
		}()
		for {
			state := hcore.CurrentCoreState()
			refreshConnectionUI(state)
			if state != hcore.CoreStates_STARTING && state != hcore.CoreStates_STOPPING {
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(300 * time.Millisecond):
			}
		}
	}()
}
