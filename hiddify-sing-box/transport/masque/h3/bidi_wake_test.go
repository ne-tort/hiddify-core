package h3

import "testing"

func TestEnvBidiWakeEnabled(t *testing.T) {
	tests := []struct {
		env  string
		want bool
	}{
		{"", true},
		{"1", true},
		{"0", false},
		{"off", false},
	}
	for _, tc := range tests {
		t.Run(tc.env, func(t *testing.T) {
			t.Setenv(envH3BidiUploadWake, tc.env)
			if got := envBidiWakeEnabled(envH3BidiUploadWake); got != tc.want {
				t.Fatalf("envBidiWakeEnabled(%q)=%v want %v", tc.env, got, tc.want)
			}
		})
	}
}
