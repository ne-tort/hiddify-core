package server

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"strings"

	fwd "github.com/sagernet/sing-box/transport/masque/forwarder"
	E "github.com/sagernet/sing/common/exceptions"
)

// OnwardTCPDialAddr maps the proxied destination to a host TCP dial target.
// When the client targets this host's own public/local address (bench iperf on the MASQUE VPS),
// hairpin via 127.0.0.1 avoids broken same-IP egress that often RSTs onward TCP.
func OnwardTCPDialAddr(host string, port uint16) string {
	trimmed := strings.Trim(strings.TrimSpace(host), "[]")
	addr, err := netip.ParseAddr(trimmed)
	if err != nil {
		return net.JoinHostPort(trimmed, strconv.Itoa(int(port)))
	}
	return fwd.DialAddr(addr, port)
}

// DialTCPTargetSerial dials resolved target addresses in order (IPv4-first when ordered).
func DialTCPTargetSerial(ctx context.Context, dialer net.Dialer, addrs []netip.Addr, port uint16) (net.Conn, netip.Addr, error) {
	if len(addrs) == 0 {
		return nil, netip.Addr{}, E.New("no tcp target addresses")
	}
	var errs []error
	for _, addr := range addrs {
		dialAddr := OnwardTCPDialAddr(addr.String(), port)
		conn, err := dialer.DialContext(ctx, "tcp", dialAddr)
		if err == nil {
			return conn, addr, nil
		}
		errs = append(errs, err)
	}
	return nil, netip.Addr{}, E.Errors(errs...)
}
