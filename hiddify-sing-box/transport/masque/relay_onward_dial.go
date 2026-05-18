package masque

import (
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// MasqueOnwardTCPDialAddr maps the proxied destination to a host TCP dial target.
// When the client targets this host's own public/local address (bench iperf on the MASQUE VPS),
// hairpin via 127.0.0.1 avoids broken same-IP egress that often RSTs onward TCP.
func MasqueOnwardTCPDialAddr(host string, port uint16) string {
	trimmed := strings.Trim(strings.TrimSpace(host), "[]")
	addr, err := netip.ParseAddr(trimmed)
	if err != nil {
		return net.JoinHostPort(trimmed, strconv.Itoa(int(port)))
	}
	return connectIPForwarderDialAddr(addr, port)
}
