package hutils

import "testing"

func TestNLANameMatches(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"PathologyTunnel", true},
		{"pathologytunnel", true},
		{"PathologyTunnel 2", true},
		{"singbox-tun0", true},
		{"singbox_tun", true},
		{"Ethernet", false},
		{"Wi-Fi", false},
		{"", false},
		{"MyPathologyTunnel", false},
	}
	for _, tc := range cases {
		if got := NLANameMatches(tc.name); got != tc.want {
			t.Errorf("NLANameMatches(%q)=%v want %v", tc.name, got, tc.want)
		}
	}
}
