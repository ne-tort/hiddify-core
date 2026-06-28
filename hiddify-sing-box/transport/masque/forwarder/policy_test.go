package forwarder

import (
	"net"
	"net/netip"
	"strconv"
	"testing"
)

func TestAllowDestIPBlocksNonPublic(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		addr string
	}{
		{"loopback", "127.0.0.1"},
		{"private", "10.0.0.1"},
		{"multicast", "224.0.0.1"},
		{"link_local_v4", "169.254.1.1"},
		{"link_local_v6", "fe80::1"},
		{"multicast_v6", "ff02::1"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			addr := netip.MustParseAddr(tc.addr)
			if err := allowDestIP(addr, false); err == nil {
				t.Fatalf("allowDestIP(%s) want error", tc.addr)
			}
		})
	}
}

func TestAllowDestIPAllowsPublicWhenPrivateDisabled(t *testing.T) {
	t.Parallel()
	addr := netip.MustParseAddr("203.0.113.10")
	if err := allowDestIP(addr, false); err != nil {
		t.Fatalf("public addr: %v", err)
	}
}

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
