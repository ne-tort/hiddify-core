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



func logUiControl(action string, pid int, alive bool) {

	hcore.Log(hcore.LogLevel_DEBUG, hcore.LogType_CORE,

		fmt.Sprintf("tray ui_control action=%s ui_pid=%d alive=%v lifecycle=%d", action, pid, alive, uiLifecycle))

}



func requestUiShowOrSpawn() {

	pid, alive := resolveUiPid()

	logUiControl("show_or_spawn", pid, alive)

	if alive {

		signalUiControl("show")

		return

	}

	spawnUiReconnect()

}



// ToggleUiOnTrayDoubleClickDetached exits a running UI process or spawns a fresh one.

func ToggleUiOnTrayDoubleClickDetached() {

	pid, alive := resolveUiPid()

	logUiControl("double_click_detached", pid, alive)

	if alive {

		requestUiQuit(pid)

		return

	}

	spawnUiReconnect()

}



// ToggleUiOnTrayDoubleClickEmbedded toggles window visibility via file signal (same process).

func ToggleUiOnTrayDoubleClickEmbedded() {

	pid, alive := resolveUiPid()

	logUiControl("double_click_embedded", pid, alive)

	if !alive {

		signalUiControl("show")

		return

	}

	signalUiControl("toggle")

}



func onTrayDoubleClick() {

	switch uiLifecycle {

	case UiLifecycleEmbedded:

		ToggleUiOnTrayDoubleClickEmbedded()

	default:

		ToggleUiOnTrayDoubleClickDetached()

	}

}



func spawnUiReconnect() {

	pid, alive := resolveUiPid()

	if alive {

		logUiControl("spawn_skipped_alive", pid, true)

		signalUiControl("show")

		return

	}



	exe := uiExe

	if exe == "" {

		exe = defaultUIExePath()

	}

	if exe == "" {

		return

	}

	logUiControl("spawn", pid, false)

	cmd := exec.Command(exe, "--reconnect-host")

	_ = cmd.Start()

}



func requestUiQuit(pid int) {

	logUiControl("quit", pid, pid > 0 && processAliveFn(pid))

	signalUiControl("quit")

	deadline := time.Now().Add(1500 * time.Millisecond)

	for time.Now().Before(deadline) {

		if pid <= 0 || !processAliveFn(pid) {

			break

		}

		time.Sleep(50 * time.Millisecond)

	}

	if pid > 0 && processAliveFn(pid) {

		_ = killProcess(pid)

		time.Sleep(100 * time.Millisecond)

	}

	if pid <= 0 || !processAliveFn(pid) {

		_ = hcore.SessionClearUiPidIf(int32(pid))

	}

}


