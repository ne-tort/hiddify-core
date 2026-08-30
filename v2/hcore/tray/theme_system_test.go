//go:build darwin || linux

package tray

import "testing"

func TestPrefersDarkSetting(t *testing.T) {
	cases := map[string]bool{
		"'prefer-dark'":    true,
		"'prefer-light'":   false,
		"'default'":        false,
		"'Adwaita-dark'":   true,
		"'Adwaita'":        false,
		"  'Yaru-dark'  ":  true,
	}
	for raw, want := range cases {
		if got := prefersDarkSetting(raw); got != want {
			t.Fatalf("raw=%q got=%v want=%v", raw, got, want)
		}
	}
}
