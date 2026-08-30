//go:build darwin || linux

package tray

import (
	"os/exec"
	"strings"
)

func setHideWindow(cmd *exec.Cmd) {}

func initTheme(themeMode string) {
	_ = themeMode
}

func applyThemeMode(themeMode string) {
	_ = themeMode
}

func stringsToLower(s string) string {
	return strings.ToLower(s)
}
