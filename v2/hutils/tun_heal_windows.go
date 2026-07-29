//go:build windows

package hutils

import (
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// HealStickyTun best-effort cleanup of leftover Hiddify TUN adapters / routes
// after a crash or aborted connect. Safe to call when the interface is absent.
func HealStickyTun() {
	name := TunInterfaceName
	_ = exec.Command("netsh", "interface", "set", "interface", "name="+name, "admin=DISABLED").Run()
	time.Sleep(200 * time.Millisecond)

	ps := fmt.Sprintf(
		`$ErrorActionPreference='SilentlyContinue'; `+
			`$n='%s'; `+
			`Get-NetRoute -InterfaceAlias $n | Remove-NetRoute -Confirm:$false; `+
			`Get-NetIPAddress -InterfaceAlias $n | Remove-NetIPAddress -Confirm:$false; `+
			`Disable-NetAdapter -Name $n -Confirm:$false; `+
			`Remove-NetAdapter -Name $n -Confirm:$false`,
		name,
	)
	_ = exec.Command("powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps).Run()

	// Also try common leftover names from older builds / sing-box defaults.
	for _, alt := range []string{"singbox_tun", "sb", "tun0"} {
		if strings.EqualFold(alt, name) {
			continue
		}
		_ = exec.Command("netsh", "interface", "set", "interface", "name="+alt, "admin=DISABLED").Run()
	}
}
