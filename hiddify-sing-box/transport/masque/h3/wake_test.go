package h3

import (
	"testing"
)

type stubMasqueWakeSender struct {
	calls int
}

func (s *stubMasqueWakeSender) MasqueWakeSend() {
	s.calls++
}

func TestFlushConnectIPIngressAckWakeH3Only(t *testing.T) {
	wake := &stubMasqueWakeSender{}
	FlushConnectIPIngressAckWake(IngressAckWakeHTTPLayerH2, wake)
	if wake.calls != 0 {
		t.Fatal("H2 overlay must not call MasqueWakeSend")
	}
	FlushConnectIPIngressAckWake("h3", wake)
	if wake.calls != 1 {
		t.Fatalf("H3 overlay must wake once, got %d", wake.calls)
	}
}

func TestBidiBulkWakeDisabledForLocalize(t *testing.T) {
	t.Setenv("MASQUE_QUIC_WAKE_SEND_ON_RECEIVE_READ", "0")
	if IngressAckWakeOnReceiveRead() {
		t.Fatal("bidi bulk localize must not unconditionally MasqueWakeStreamSend on every Read")
	}
}

func TestIngressAckWakeOnReceiveReadEnv(t *testing.T) {
	tests := []struct {
		env  string
		want bool
	}{
		{"", true},
		{"0", false},
		{"1", true},
		{"off", true},
	}
	for _, tc := range tests {
		t.Run(tc.env, func(t *testing.T) {
			t.Setenv("MASQUE_QUIC_WAKE_SEND_ON_RECEIVE_READ", tc.env)
			if got := IngressAckWakeOnReceiveRead(); got != tc.want {
				t.Fatalf("IngressAckWakeOnReceiveRead() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestConnectIPIngressWakeIsolatedFromBidiReadWake documents wake isolation on a shared QUIC conn:
// MASQUE_QUIC_WAKE_SEND_ON_RECEIVE_READ=0 disables CONNECT-stream bidi Read wake, but CONNECT-IP
// ingress ACK wake still runs via FlushConnectIPIngressAckWake.
func TestConnectIPIngressWakeIsolatedFromBidiReadWake(t *testing.T) {
	t.Setenv("MASQUE_QUIC_WAKE_SEND_ON_RECEIVE_READ", "0")
	if IngressAckWakeOnReceiveRead() {
		t.Fatal("bidi read wake must be disabled for localize")
	}
	wake := &stubMasqueWakeSender{}
	FlushConnectIPIngressAckWake("h3", wake)
	if wake.calls != 1 {
		t.Fatalf("CONNECT-IP ingress wake must stay enabled, got %d MasqueWakeSend calls", wake.calls)
	}
}
