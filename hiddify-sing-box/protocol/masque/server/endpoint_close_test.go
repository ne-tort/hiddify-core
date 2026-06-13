package server

import (
	"net"
	"testing"
)

func TestCloseMasqueEndpointFullStackDelegatesToShutdown(t *testing.T) {
	t.Parallel()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	stack := MasqueStack{PacketConn: pc}
	if err := CloseMasqueEndpoint(MasqueEndpointCloseInput{Stack: stack}); err != nil {
		t.Fatalf("close full stack: %v", err)
	}
	buf := make([]byte, 1)
	if _, _, err := pc.ReadFrom(buf); err == nil {
		t.Fatal("expected closed packet conn after full stack close")
	}
}

func TestCloseMasqueEndpointNilInputIsSafe(t *testing.T) {
	t.Parallel()
	if err := CloseMasqueEndpoint(MasqueEndpointCloseInput{}); err != nil {
		t.Fatalf("nil close input: %v", err)
	}
}
