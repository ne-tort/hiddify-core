//go:build windows

package hutils

import (
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

const createNoWindow = 0x08000000 // CREATE_NO_WINDOW

var (
	healMu       sync.Mutex
	lastHealAt   time.Time
	healCooldown   = 5 * time.Second
)

// HealStickyTun best-effort cleanup of leftover Hiddify TUN adapters / routes
// after a crash or aborted connect. Safe to call when the interface is absent.
// Runs without flashing console windows (CREATE_NO_WINDOW).
func HealStickyTun() {
	healStickyTun(false)
}

// HealStickyTunForce bypasses the cooldown — use after a failed TUN create so a
// rapid reconnect can reclaim a leftover Wintun adapter.
func HealStickyTunForce() {
	healStickyTun(true)
}

// StickyTunLikelyPresent is a fast smoke check for a leftover PathologyTunnel
// adapter (post-crash ghost). True → caller should HealStickyTunForce before Start.
func StickyTunLikelyPresent() bool {
	name := TunInterfaceName
	out, ok := runHiddenOutput(500*time.Millisecond, "netsh", "interface", "show", "interface", "name="+name)
	if !ok {
		// Timed out or failed to spawn — do not force heal on every Connect.
		// Sticky NewService failure path still heals + retries once.
		return false
	}
	low := strings.ToLower(out)
	if strings.Contains(low, "no interface") || strings.Contains(low, "not found") ||
		strings.Contains(low, "element not found") || strings.TrimSpace(out) == "" {
		return false
	}
	// netsh prints a table with Admin State / State / Type / Interface Name when present.
	return strings.Contains(out, name) || strings.Contains(low, strings.ToLower(name))
}

func healStickyTun(force bool) {
	healMu.Lock()
	if !force && time.Since(lastHealAt) < healCooldown {
		healMu.Unlock()
		return
	}
	lastHealAt = time.Now()
	healMu.Unlock()

	name := TunInterfaceName
	// Netsh-only: PowerShell Get-NetRoute can hang 10–30s on some Windows hosts
	// and blocked connect/reconnect UX. Prefer fast best-effort cleanup.
	runHidden(2*time.Second, "netsh", "interface", "set", "interface", "name="+name, "admin=DISABLED")
	time.Sleep(100 * time.Millisecond)
	runHidden(2*time.Second, "netsh", "interface", "ip", "delete", "address", "name="+name, "addr=all")
	runHidden(2*time.Second, "netsh", "interface", "ipv6", "delete", "address", "interface="+name, "address=all")
	runHidden(2*time.Second, "netsh", "interface", "delete", "interface", "name="+name)

	for _, alt := range []string{"singbox_tun", "sb", "tun0"} {
		if strings.EqualFold(alt, name) {
			continue
		}
		runHidden(1*time.Second, "netsh", "interface", "set", "interface", "name="+alt, "admin=DISABLED")
	}

	cleanupNLAProfiles()
}

func runHidden(timeout time.Duration, name string, args ...string) {
	_, _ = runHiddenOutput(timeout, name, args...)
}

// runHiddenOutput runs a command with CREATE_NO_WINDOW and returns combined
// stdout+stderr. ok is false if the process could not be started or was killed
// by timeout.
func runHiddenOutput(timeout time.Duration, name string, args ...string) (string, bool) {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: createNoWindow,
	}
	if timeout <= 0 {
		out, err := cmd.CombinedOutput()
		return string(out), err == nil || len(out) > 0
	}
	var buf strings.Builder
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Start(); err != nil {
		return "", false
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
		return buf.String(), true
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		<-done
		return buf.String(), false
	}
}
