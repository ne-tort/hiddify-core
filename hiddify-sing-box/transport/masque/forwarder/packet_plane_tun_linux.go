//go:build linux

package forwarder

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"

	cippump "github.com/sagernet/sing-box/transport/masque/connectip/pump"
	tun "github.com/sagernet/sing-tun"
)

// OpenConnectIPServerPacketDevice opens a host TUN for RFC §7.2 IP emit.
// Name: MASQUE_CONNECT_IP_TUN or "masquecip0". Address: 198.18.0.254/32 (client peer = 198.18.0.1).
// No ACL/peer routing — kernel + external L3Router / lab NAT own that.
//
// EXP_ExternalConfiguration: avoid nil InterfaceMonitor panic (no networkManager in
// CONNECT-IP route). Address/peer route applied via ip(8) after Start.
func OpenConnectIPServerPacketDevice() (cippump.TunnelDevice, error) {
	name := strings.TrimSpace(os.Getenv("MASQUE_CONNECT_IP_TUN"))
	if name == "" {
		name = "masquecip0"
	}
	addr := netip.MustParsePrefix("198.18.0.254/32")
	t, err := tun.New(tun.Options{
		Name:                      name,
		MTU:                       1500,
		Inet4Address:              []netip.Prefix{addr},
		AutoRoute:                 false,
		EXP_ExternalConfiguration: true,
	})
	if err != nil {
		return nil, fmt.Errorf("connect-ip packet TUN %s: %w", name, err)
	}
	if err := t.Start(); err != nil {
		_ = t.Close()
		return nil, fmt.Errorf("connect-ip packet TUN start: %w", err)
	}
	// EXP path skips AddrAdd — configure for lab NAT/forward.
	_ = exec.Command("ip", "addr", "replace", "198.18.0.254/32", "dev", name).Run()
	_ = exec.Command("ip", "link", "set", "dev", name, "up").Run()
	_ = exec.Command("ip", "route", "replace", "198.18.0.1/32", "dev", name).Run()
	return NewIOReadWriterDevice(t), nil
}
