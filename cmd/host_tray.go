//go:build windows || darwin || linux

package cmd

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"

	hcore "github.com/ne-tort/pathology-core/v2/hcore"

	"fyne.io/systray"
)

var (
	hostTrayUiExe  string
	hostTrayLang   = "en"
	hostTrayBase   string
	hostTrayDark   bool
	hostTrayLabels hostTrayMenuLabels
	hostTrayDone   chan struct{}
	hostTrayDoneOnce sync.Once
)

type hostTrayMenuLabels struct {
	showWindow  string
	connect     string
	disconnect  string
	reconnect   string
	quit        string
	tooltip     string
}

func initHostTrayLabels(prefs hostTrayPrefs) {
	hostTrayLabels = hostTrayMenuLabels{
		tooltip: "Pathology",
	}
	if prefs.isRu() {
		hostTrayLang = "ru"
		hostTrayLabels.showWindow = "Показать окно"
		hostTrayLabels.connect = "Подключить"
		hostTrayLabels.disconnect = "Отключить"
		hostTrayLabels.reconnect = "Переподключить"
		hostTrayLabels.quit = "Выход"
	} else {
		hostTrayLang = "en"
		hostTrayLabels.showWindow = "Show window"
		hostTrayLabels.connect = "Connect"
		hostTrayLabels.disconnect = "Disconnect"
		hostTrayLabels.reconnect = "Reconnect"
		hostTrayLabels.quit = "Quit"
	}
}

func startHostTray(uiExe string) {
	hostTrayUiExe = uiExe
	if hostTrayUiExe == "" {
		hostTrayUiExe = defaultUiExePath()
	}
	prefs := loadHostTrayPrefs(hostTrayBase)
	initHostTrayLabels(prefs)
	hostTrayDark = prefs.isDarkMenu()
	setupHostTrayClickHandlers()
	go systray.Run(onHostTrayReady, onHostTrayExit)
}

func onHostTrayReady() {
	initHostTrayTheme()
	systray.SetTitle("Pathology")
	systray.SetTooltip(hostTrayLabels.tooltip)
	applyTrayIcon(hcore.CurrentCoreState(), hostTrayDark)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-hostTrayDone
		cancel()
	}()
	startHostTrayStatusPoll(ctx, hostTrayDark)

	showItem := systray.AddMenuItem(hostTrayLabels.showWindow, "")
	systray.AddSeparator()
	connectItem := systray.AddMenuItem(hostTrayLabels.connect, "")
	disconnectItem := systray.AddMenuItem(hostTrayLabels.disconnect, "")
	reconnectItem := systray.AddMenuItem(hostTrayLabels.reconnect, "")
	systray.AddSeparator()
	quitItem := systray.AddMenuItem(hostTrayLabels.quit, "")

	go func() {
		for {
			select {
			case <-showItem.ClickedCh:
				spawnUiReconnect()
			case <-connectItem.ClickedCh:
				_, _ = hcore.Start(context.Background(), &hcore.StartRequest{})
			case <-disconnectItem.ClickedCh:
				_, _ = hcore.Stop()
			case <-reconnectItem.ClickedCh:
				_, _ = hcore.Stop()
				_, _ = hcore.Start(context.Background(), &hcore.StartRequest{})
			case <-quitItem.ClickedCh:
				_, _ = hcore.Stop()
				systray.Quit()
				return
			}
		}
	}()
}

func onHostTrayExit() {
	hostTrayDoneOnce.Do(func() {
		if hostTrayDone != nil {
			close(hostTrayDone)
		}
	})
}

func spawnUiReconnect() {
	exe := hostTrayUiExe
	if exe == "" {
		exe = defaultUiExePath()
	}
	if exe == "" {
		return
	}
	cmd := exec.Command(exe, "--reconnect-host")
	setHideWindow(cmd)
	_ = cmd.Start()
}

func defaultUiExePath() string {
	self, err := os.Executable()
	if err != nil {
		return ""
	}
	dir := filepath.Dir(self)
	if runtime.GOOS == "windows" {
		return filepath.Join(dir, "Pathology.exe")
	}
	if runtime.GOOS == "darwin" {
		return filepath.Join(dir, "Pathology.app", "Contents", "MacOS", "Pathology")
	}
	return filepath.Join(dir, "pathology")
}
