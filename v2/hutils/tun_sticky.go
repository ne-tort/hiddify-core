package hutils

import "strings"

// IsStickyTunStartError reports WinTun/Linux leftover-adapter failures that
// usually clear after HealStickyTunForce (ghost adapter after crash).
func IsStickyTunStartError(err error) bool {
	if err == nil {
		return false
	}
	return IsStickyTunStartErrorMessage(err.Error())
}

// IsStickyTunStartErrorMessage is the string form used by tests and callers
// that only have a message (no wrapped error).
func IsStickyTunStartErrorMessage(message string) bool {
	m := strings.ToLower(strings.TrimSpace(message))
	if m == "" {
		return false
	}
	if strings.Contains(m, "already exists") {
		return true
	}
	if strings.Contains(m, "element not found") {
		return true
	}
	if strings.Contains(m, "configure tun") && strings.Contains(m, "exist") {
		return true
	}
	if strings.Contains(m, "create adapter") && (strings.Contains(m, "already") || strings.Contains(m, "exist")) {
		return true
	}
	if strings.Contains(m, "open existing adapter") {
		return true
	}
	return false
}
