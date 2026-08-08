package config

import "testing"

func TestGetDnsAddressPreservesLocal(t *testing.T) {
	cases := map[string]string{
		"local":            "local",
		"LOCAL":            "local",
		"fakeip":           "fakeip",
		"udp://1.1.1.1":    "udp://1.1.1.1",
		"1.1.1.1":          "udp://1.1.1.1",
		"dhcp://auto":      "dhcp://auto",
		"tls://1.1.1.1":    "tls://1.1.1.1",
	}
	for in, want := range cases {
		if got := getDnsAddress(in); got != want {
			t.Fatalf("getDnsAddress(%q)=%q want %q", in, got, want)
		}
	}
}
