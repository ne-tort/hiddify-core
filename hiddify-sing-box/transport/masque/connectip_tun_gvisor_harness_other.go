//go:build !linux || !with_gvisor

package masque

import (
	"net/netip"
	"testing"

	"github.com/sagernet/sing-tun"
)

func gvisorHarnessTunOptions(name, clientCIDR string) tun.Options {
	return tun.Options{
		Name: name,
		MTU:  1500,
		Inet4Address: []netip.Prefix{
			netip.MustParsePrefix(clientCIDR),
		},
		Inet4RouteAddress: []netip.Prefix{
			netip.MustParsePrefix(TunGVisorTargetIP + "/32"),
		},
	}
}

func installGVisorHarnessHostRoute(string, string) error { return nil }

func skipUnlessTunHostRoute(testing.TB, *ConnectIPTunGVisorEnv) bool { return false }
