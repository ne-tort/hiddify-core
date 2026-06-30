package forwarder

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
)

func allowDestIP(addr netip.Addr, allowPrivate bool) error {
	if !addr.IsValid() {
		return errors.New("invalid destination")
	}
	if allowPrivate {
		return nil
	}
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsMulticast() ||
		addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsUnspecified() {
		return errors.New("private target denied")
	}
	return nil
}

var (
	dialAddrLocalIPsMu sync.RWMutex
	dialAddrLocalIPs   map[netip.Addr]struct{}
)

func collectLocalInterfaceAddrs() map[netip.Addr]struct{} {
	ips := make(map[netip.Addr]struct{})
	ifaces, err := net.Interfaces()
	if err != nil {
		return ips
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip netip.Addr
			switch v := a.(type) {
			case *net.IPNet:
				ip, _ = netip.AddrFromSlice(v.IP)
			case *net.IPAddr:
				ip, _ = netip.AddrFromSlice(v.IP)
			}
			ip = ip.Unmap()
			if ip.IsValid() {
				ips[ip] = struct{}{}
			}
		}
	}
	return ips
}

func localInterfaceAddrs() map[netip.Addr]struct{} {
	dialAddrLocalIPsMu.RLock()
	cached := dialAddrLocalIPs
	dialAddrLocalIPsMu.RUnlock()
	if cached != nil {
		return cached
	}
	dialAddrLocalIPsMu.Lock()
	defer dialAddrLocalIPsMu.Unlock()
	if dialAddrLocalIPs == nil {
		dialAddrLocalIPs = collectLocalInterfaceAddrs()
	}
	return dialAddrLocalIPs
}

// DialAddr maps the proxied destination to a host TCP/UDP dial target.
// When the client targets this host's own public/local address (bench iperf on the MASQUE VPS),
// hairpin via loopback avoids broken same-IP egress that often RSTs CONNECT-IP TCP.
func DialAddr(dstIP netip.Addr, port uint16) string {
	if dstIP.IsValid() {
		if _, local := localInterfaceAddrs()[dstIP]; local {
			if dstIP.Is6() && !dstIP.Is4In6() {
				return net.JoinHostPort("::1", strconv.Itoa(int(port)))
			}
			return net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))
		}
	}
	return net.JoinHostPort(dstIP.String(), strconv.Itoa(int(port)))
}

func allowPort(port uint16, allowList []uint16, denyList []uint16) bool {
	for _, d := range denyList {
		if d == port {
			return false
		}
	}
	if len(allowList) == 0 {
		return true
	}
	for _, a := range allowList {
		if a == port {
			return true
		}
	}
	return false
}
