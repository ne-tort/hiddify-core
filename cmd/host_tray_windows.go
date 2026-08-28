//go:build windows

package cmd

import (
	"os/exec"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"fyne.io/systray"
	"golang.org/x/sys/windows"
)

var (
	trayClickMu      sync.Mutex
	lastRightClickAt time.Time
	rightClickWindow = 400 * time.Millisecond
)

const (
	wmLButtonUp = 0x0202
)

func setHideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
}

func setupHostTrayClickHandlers() {
	systray.SetOnSecondaryTapped(func() {
		trayClickMu.Lock()
		now := time.Now()
		isDouble := !lastRightClickAt.IsZero() && now.Sub(lastRightClickAt) <= rightClickWindow
		lastRightClickAt = now
		trayClickMu.Unlock()
		if !isDouble {
			return
		}
		if hostTrayDark {
			applyDarkContextMenu()
		}
		postSystrayLeftClick()
	})
}

func initHostTrayTheme() {
	if hostTrayDark {
		applyDarkContextMenu()
	}
}

func postSystrayLeftClick() {
	hwnd := findSystrayWindow()
	if hwnd == 0 {
		return
	}
	user32 := windows.NewLazySystemDLL("user32.dll")
	postMessage := user32.NewProc("PostMessageW")
	postMessage.Call(hwnd, wmLButtonUp, 0, 0)
}

func findSystrayWindow() uintptr {
	user32 := windows.NewLazySystemDLL("user32.dll")
	findWindow := user32.NewProc("FindWindowW")
	className, _ := windows.UTF16PtrFromString("SystrayClass")
	hwnd, _, _ := findWindow.Call(uintptr(unsafe.Pointer(className)), 0)
	return hwnd
}

func applyDarkContextMenu() {
	_ = setPreferredAppMode(1)
}

func setPreferredAppMode(mode int32) bool {
	uxtheme := windows.NewLazySystemDLL("uxtheme.dll")
	proc := uxtheme.NewProc("SetPreferredAppMode")
	r, _, _ := proc.Call(uintptr(mode))
	return r != 0
}
