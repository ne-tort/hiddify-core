package forwarder

import (
	"net"
	"net/netip"
	"strconv"
	"testing"
)

func TestDialAddrHairpin(t *testing.T) {
	t.Parallel()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("interfaces: %v", err)
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
			if !ip.IsValid() || !ip.Is4() || ip.IsLoopback() {
				continue
			}
			const port = 18080
			got := DialAddr(ip, port)
			want := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
			if got != want {
				t.Fatalf("hairpin %v: got %q want %q", ip, got, want)
			}
			return
		}
	}
	t.Skip("no non-loopback IPv4 interface for hairpin test")
}
