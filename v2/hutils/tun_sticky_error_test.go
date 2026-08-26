package hutils

import (
	"errors"
	"testing"
)

func TestIsStickyTunStartError(t *testing.T) {
	cases := []struct {
		msg  string
		want bool
	}{
		{
			msg:  `start inbound/tun[tun-in]: configure tun interface: (create adapter: Cannot create a file when that file already exists. | open existing adapter: Element not found.)`,
			want: true,
		},
		{
			msg:  `open existing adapter: Element not found.`,
			want: true,
		},
		{
			msg:  `create adapter: Cannot create a file when that file already exists.`,
			want: true,
		},
		{
			msg:  `permission denied opening tun`,
			want: false,
		},
		{
			msg:  `invalid config: missing outbound`,
			want: false,
		},
	}
	for _, tc := range cases {
		got := IsStickyTunStartError(errors.New(tc.msg))
		if got != tc.want {
			t.Fatalf("IsStickyTunStartError(%q)=%v want %v", tc.msg, got, tc.want)
		}
	}
	if IsStickyTunStartError(nil) {
		t.Fatal("nil should be false")
	}
}
