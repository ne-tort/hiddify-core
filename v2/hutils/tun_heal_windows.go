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
	healMu.Lock()
	if time.Since(lastHealAt) < healCooldown {
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
}

func runHidden(timeout time.Duration, name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: createNoWindow,
	}
	if timeout <= 0 {
		_ = cmd.Run()
		return
	}
	if err := cmd.Start(); err != nil {
		return
	}
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		<-done
	}
}
