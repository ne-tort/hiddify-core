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
