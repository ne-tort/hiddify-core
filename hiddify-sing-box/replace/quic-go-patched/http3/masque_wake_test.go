package http3

import (
	"testing"
)

func TestMasqueWakeSendOnReceiveReadEnv(t *testing.T) {
	tests := []struct {
		env  string
		want bool
	}{
		{"", true},
		{"0", false},
		{"1", true},
	}
	for _, tc := range tests {
		t.Run(tc.env, func(t *testing.T) {
			t.Setenv("MASQUE_QUIC_WAKE_SEND_ON_RECEIVE_READ", tc.env)
			if got := masqueWakeSendOnReceiveRead(); got != tc.want {
				t.Fatalf("masqueWakeSendOnReceiveRead() = %v, want %v", got, tc.want)
			}
		})
	}
}
