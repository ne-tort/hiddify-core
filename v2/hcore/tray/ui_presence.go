//go:build windows || darwin || linux

package tray

import (
	"encoding/json"
	"os"
	"path/filepath"
)

const uiPresenceFile = "ui_presence.json"

type uiPresenceRecord struct {
	PID   int    `json:"pid"`
	Since string `json:"since"`
}

func uiPresencePath() string {
	return filepath.Join(basePath, uiPresenceFile)
}

func readUiPresencePid() (int, bool) {
	if basePath == "" {
		return 0, false
	}
	raw, err := os.ReadFile(uiPresencePath())
	if err != nil || len(raw) == 0 {
		return 0, false
	}
	var rec uiPresenceRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return 0, false
	}
	if rec.PID <= 0 {
		return 0, false
	}
	return rec.PID, true
}

// resolveUiPid returns the live UI pid: ui_presence.json first, then LevelDB session.
func resolveUiPid() (pid int, alive bool) {
	if p, ok := readUiPresencePid(); ok && processAliveFn(p) {
		return p, true
	}
	st := sessionGetState()
	p := int(st.UiPid)
	if p > 0 && processAliveFn(p) {
		return p, true
	}
	return 0, false
}
