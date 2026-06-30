package masque

import (
	"errors"
	"testing"
)

func TestRejectConnectIPHybridTransport(t *testing.T) {
	t.Parallel()
	if err := RejectConnectIPHybridTransport("connect_ip", "connect_stream"); !errors.Is(err, ErrConnectIPHybridTransport) {
		t.Fatalf("hybrid: %v", err)
	}
	if err := RejectConnectIPHybridTransport("connect_ip", "connect_ip"); err != nil {
		t.Fatalf("valid tcp over ip: %v", err)
	}
	if err := RejectConnectIPHybridTransport("connect_udp", "connect_stream"); err != nil {
		t.Fatalf("udp+stream: %v", err)
	}
}
