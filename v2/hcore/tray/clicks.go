//go:build windows || darwin || linux

package tray

import (
	"sync"
	"time"

	"fyne.io/systray"
)

const doubleClickWindow = 400 * time.Millisecond

var (
	clickMu        sync.Mutex
	lastPrimaryTap time.Time
)

func setupClickHandlers(onDoubleClick func()) {
	systray.SetOnTapped(func() {
		clickMu.Lock()
		now := time.Now()
		isDouble := !lastPrimaryTap.IsZero() && now.Sub(lastPrimaryTap) <= doubleClickWindow
		lastPrimaryTap = now
		clickMu.Unlock()
		if isDouble {
			onDoubleClick()
		}
	})
}

func isDoubleClick(now, previous time.Time) bool {
	return !previous.IsZero() && now.Sub(previous) <= doubleClickWindow
}
