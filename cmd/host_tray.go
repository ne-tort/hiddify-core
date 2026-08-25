//go:build windows || darwin || linux

package cmd

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	hcore "github.com/ne-tort/pathology-core/v2/hcore"

	"fyne.io/systray"
)

var (
	hostTrayUiExe string
	hostTrayLang  = "en"
)

func startHostTray(uiExe string) {
	hostTrayUiExe = uiExe
	if hostTrayUiExe == "" {
		hostTrayUiExe = defaultUiExePath()
	}
	go systray.Run(onHostTrayReady, onHostTrayExit)
}

func onHostTrayReady() {
	systray.SetTitle("Pathology")
	systray.SetTooltip("Pathology")

	openLabel := "Open"
	connectLabel := "Connect"
	disconnectLabel := "Disconnect"
	quitLabel := "Quit"
	if hostTrayLang == "ru" {
		openLabel = "Открыть"
		connectLabel = "Подключить"
		disconnectLabel = "Отключить"
		quitLabel = "Выход"
	}

	openItem := systray.AddMenuItem(openLabel, "")
	systray.AddSeparator()
	connectItem := systray.AddMenuItem(connectLabel, "")
	disconnectItem := systray.AddMenuItem(disconnectLabel, "")
	systray.AddSeparator()
	quitItem := systray.AddMenuItem(quitLabel, "")

	go func() {
		for {
			select {
			case <-openItem.ClickedCh:
				spawnUiReconnect()
			case <-connectItem.ClickedCh:
				_, _ = hcore.Start(context.Background(), &hcore.StartRequest{})
			case <-disconnectItem.ClickedCh:
				_, _ = hcore.Stop()
			case <-quitItem.ClickedCh:
				systray.Quit()
				return
			}
		}
	}()
}

func onHostTrayExit() {
	if hostTrayDone != nil {
		close(hostTrayDone)
	}
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
