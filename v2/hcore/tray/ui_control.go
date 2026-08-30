//go:build windows || darwin || linux

package tray

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	hcore "github.com/ne-tort/pathology-core/v2/hcore"
)

const uiControlFile = "ui_control.request"

func uiControlPath() string {
	return filepath.Join(basePath, uiControlFile)
}

func signalUiControl(action string) {
	if basePath == "" {
		return
	}
	path := uiControlPath()
	payload := fmt.Sprintf(`{"action":"%s","ts":%d}`, action, time.Now().UnixNano())
	_ = os.WriteFile(path, []byte(payload), 0o644)
}

func requestUiShowOrSpawn() {
	st := hcore.SessionGetState()
	pid := int(st.UiPid)
	if pid > 0 && processAlive(pid) {
		signalUiControl("show")
		return
	}
	spawnUiReconnect()
}

// ToggleUiOnTrayDoubleClick exits a running UI process or spawns a fresh one.
func ToggleUiOnTrayDoubleClick() {
	st := hcore.SessionGetState()
	pid := int(st.UiPid)
	if pid > 0 && processAlive(pid) {
		requestUiQuit()
		return
	}
	spawnUiReconnect()
}

func spawnUiReconnect() {
	exe := uiExe
	if exe == "" {
		exe = defaultUIExePath()
	}
	if exe == "" {
		return
	}
	cmd := exec.Command(exe, "--reconnect-host")
	setHideWindow(cmd)
	_ = cmd.Start()
}

func requestUiQuit() {
	signalUiControl("quit")
	st := hcore.SessionGetState()
	pid := int(st.UiPid)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if pid <= 0 || !processAlive(pid) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if pid > 0 && processAlive(pid) {
		_ = killProcess(pid)
		time.Sleep(200 * time.Millisecond)
	}
	_ = hcore.SessionClearUiPid()
}
