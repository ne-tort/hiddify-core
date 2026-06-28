//go:build linux && with_gvisor

package masque

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"testing"

	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/x/list"
)

type gvisorHarnessIfaceMonitor struct {
	myInterface string
}

func (m *gvisorHarnessIfaceMonitor) Start() error { return nil }
func (m *gvisorHarnessIfaceMonitor) Close() error { return nil }
func (m *gvisorHarnessIfaceMonitor) DefaultInterface() *control.Interface { return nil }
func (m *gvisorHarnessIfaceMonitor) OverrideAndroidVPN() bool             { return false }
func (m *gvisorHarnessIfaceMonitor) AndroidVPNEnabled() bool              { return false }
func (m *gvisorHarnessIfaceMonitor) RegisterCallback(tun.DefaultInterfaceUpdateCallback) *list.Element[tun.DefaultInterfaceUpdateCallback] {
	return nil
}
func (m *gvisorHarnessIfaceMonitor) UnregisterCallback(*list.Element[tun.DefaultInterfaceUpdateCallback]) {
}
func (m *gvisorHarnessIfaceMonitor) RegisterMyInterface(name string) { m.myInterface = name }
func (m *gvisorHarnessIfaceMonitor) MyInterface() string               { return m.myInterface }

func gvisorHarnessTunOptions(name, clientCIDR string) tun.Options {
	return tun.Options{
		Name:                      name,
		MTU:                       1500,
		EXP_ExternalConfiguration: true,
		Inet4Address: []netip.Prefix{
			netip.MustParsePrefix(clientCIDR),
		},
		InterfaceMonitor: &gvisorHarnessIfaceMonitor{},
	}
}

// installGVisorHarnessHostRoute adds tun address + overlay target route (prod bench: ip route replace … dev tun0).
// skipUnlessTunHostRoute avoids masque SYN probes (orphan forwarder sessions) when route is enough.
func skipUnlessTunHostRoute(tb testing.TB, env *ConnectIPTunGVisorEnv) bool {
	tb.Helper()
	if env == nil || env.tunName == "" {
		return false
	}
	out, err := exec.Command("ip", "route", "get", env.targetIP).CombinedOutput()
	if err != nil {
		tb.Skipf("ip route get %s: %v (%s)", env.targetIP, err, strings.TrimSpace(string(out)))
		return true
	}
	line := strings.TrimSpace(string(out))
	if !strings.Contains(line, "dev "+env.tunName) {
		tb.Skipf("ip route get %s: want dev %s, got %q", env.targetIP, env.tunName, line)
		return true
	}
	return true
}

func installGVisorHarnessHostRoute(tunName, clientCIDR string) error {
	addAddr := exec.Command("ip", "addr", "replace", clientCIDR, "dev", tunName)
	if out, err := addAddr.CombinedOutput(); err != nil {
		return fmt.Errorf("ip addr replace %s dev %s: %w (%s)", clientCIDR, tunName, err, out)
	}
	up := exec.Command("ip", "link", "set", tunName, "up")
	if out, err := up.CombinedOutput(); err != nil {
		return fmt.Errorf("ip link set %s up: %w (%s)", tunName, err, out)
	}
	route := exec.Command("ip", "route", "replace", TunGVisorTargetIP+"/32", "dev", tunName)
	if out, err := route.CombinedOutput(); err != nil {
		return fmt.Errorf("ip route replace %s/32 dev %s: %w (%s)", TunGVisorTargetIP, tunName, err, out)
	}
	return nil
}
