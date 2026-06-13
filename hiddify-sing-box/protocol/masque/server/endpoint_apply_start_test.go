package server

import (
	"net"
	"testing"
)

func TestMapMasqueEndpointStartResultDualBindStack(t *testing.T) {
	t.Parallel()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer pc.Close()
	out := MasqueEndpointStartResult{
		Stack: &MasqueStack{PacketConn: pc},
	}
	applied := MapMasqueEndpointStartResult(out)
	if applied.PacketConn != pc {
		t.Fatal("expected packet conn from stack")
	}
}
